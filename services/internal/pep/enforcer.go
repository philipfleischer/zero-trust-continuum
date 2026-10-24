// The enforcer: the middleware that puts route, authentication, trust
// signal and decision together and turns the outcome into a status code.

package pep

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/observability"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/pdp"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/trust"
)

// SignalSender sends trust signals to the PDP. pdp.RemoteClient implements it.
type SignalSender interface {
	RecordSignal(ctx context.Context, signal trust.Signal) error
}

// authenticationStrength is the value of the authentication signal for each
// way of authenticating, as documented in package trust.
var authenticationStrength = map[string]float64{
	"token":      0.5,
	"capability": 0.6,
}

// Config is what NewEnforcer needs. Routes, Decider, Logger and Metrics are
// required.
type Config struct {
	Name          string        // e.g. "ztc-pep-bay-1"; the source of the signals it sends
	Routes        *RouteTable   // which paths are protected, and what they are
	Authenticator Authenticator // which credentials are accepted
	Decider       pdp.Decider   // the PDP, a cache in front of it, or a chain
	// SourceZone is the network zone this PEP receives requests from. It is
	// configuration, never something the client says.
	SourceZone string
	// Signals receives an authentication signal for each subject at most
	// once per SignalInterval (default one minute). nil sends none.
	Signals        SignalSender
	SignalInterval time.Duration
	Logger         *slog.Logger
	Metrics        *observability.Registry
	Now            func() time.Time // nil means time.Now
}

// Enforcer is the PEP. Create it with NewEnforcer.
type Enforcer struct {
	config          Config
	requests        *observability.Counter
	decisionLatency *observability.Histogram

	mutex        sync.Mutex
	lastReported map[string]time.Time // subject ID -> when its authentication was last reported
}

// NewEnforcer checks config and returns the PEP.
func NewEnforcer(config Config) (*Enforcer, error) {
	if config.Routes == nil || config.Decider == nil || config.Logger == nil || config.Metrics == nil {
		return nil, errors.New("pep: Routes, Decider, Logger and Metrics are required")
	}
	if config.SignalInterval <= 0 {
		config.SignalInterval = time.Minute
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Enforcer{
		config:          config,
		requests:        config.Metrics.Counter("ztc_pep_requests_total", "Requests seen by the PEP by outcome."),
		decisionLatency: config.Metrics.Histogram("ztc_pep_decision_seconds", "Time to get a decision, by who decided.", observability.DefaultLatencyBuckets),
		lastReported:    make(map[string]time.Time),
	}, nil
}

// contextKey is the type of the keys the middleware stores in the request
// context, so no other package can collide with them.
type contextKey int

const (
	subjectKey contextKey = iota
	decisionKey
)

// SubjectFrom returns the authenticated subject the middleware stored in ctx.
func SubjectFrom(ctx context.Context) (model.Subject, bool) {
	subject, found := ctx.Value(subjectKey).(model.Subject)
	return subject, found
}

// DecisionFrom returns the decision the middleware stored in ctx.
func DecisionFrom(ctx context.Context) (model.Decision, bool) {
	decision, found := ctx.Value(decisionKey).(model.Decision)
	return decision, found
}

// Middleware returns next wrapped in enforcement. A request reaches next only
// if the PDP allowed it; otherwise the client gets
//
//	404  no route for the path
//	405  a method with no action
//	401  no valid credential
//	403  the PDP denied it, or an obligation cannot be fulfilled
//	503  no decision could be had: fail closed
//
// The client sees only the status; the reason goes to the log, so an
// attacker learns neither the rules nor why a credential failed.
func (enforcer *Enforcer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		route, found := enforcer.config.Routes.Match(request.URL.Path)
		if !found {
			enforcer.reject(writer, "no-route", http.StatusNotFound, "no such resource")
			return
		}
		action, known := ActionFor(request.Method, route.ResourceType)
		if !known {
			enforcer.reject(writer, "no-action", http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		subject, err := enforcer.config.Authenticator.Authenticate(request, route, action)
		if err != nil {
			enforcer.config.Logger.Warn("request unauthenticated", "pep", enforcer.config.Name, "path", request.URL.Path, "reason", err)
			writer.Header().Set("WWW-Authenticate", `Bearer realm="ztc"`)
			enforcer.reject(writer, "unauthenticated", http.StatusUnauthorized, "unauthenticated")
			return
		}
		enforcer.reportAuthentication(request.Context(), subject)

		accessRequest := enforcer.BuildRequest(subject, route, action, request.URL.Path)
		decision, err := enforcer.decide(request.Context(), accessRequest)
		if err != nil {
			enforcer.config.Logger.Error("no decision", "pep", enforcer.config.Name, "subject", subject.ID, "reason", err)
			enforcer.reject(writer, "pdp-unavailable", http.StatusServiceUnavailable, "decision unavailable")
			return
		}
		if !decision.Allowed() {
			enforcer.logDecision("request denied", accessRequest, decision)
			enforcer.reject(writer, "denied", http.StatusForbidden, "forbidden")
			return
		}
		if err := enforcer.fulfilObligations(accessRequest, decision); err != nil {
			enforcer.config.Logger.Error("obligation not fulfilled", "pep", enforcer.config.Name, "subject", subject.ID, "reason", err)
			enforcer.reject(writer, "obligation-failed", http.StatusForbidden, "forbidden")
			return
		}
		enforcer.requests.Inc("outcome", "allowed")
		ctx := context.WithValue(request.Context(), subjectKey, subject)
		ctx = context.WithValue(ctx, decisionKey, decision)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

// BuildRequest returns the access request the PDP decides about. The subject
// comes from the credential, the resource from the route, and the source zone
// from the PEP's configuration. Nothing comes from the client's headers: time,
// trust score and emergency mode are left for the PDP to fill in.
func (enforcer *Enforcer) BuildRequest(subject model.Subject, route Route, action, requestPath string) model.AccessRequest {
	return model.AccessRequest{
		Subject: subject,
		Action:  action,
		Resource: model.Resource{
			ID:          ResourceID(requestPath),
			Type:        route.ResourceType,
			Zone:        route.Zone,
			Layer:       route.Layer,
			Sensitivity: route.Sensitivity,
		},
		Context: model.Context{SourceZone: enforcer.config.SourceZone},
	}
}

// decide asks the Decider and records how long it took. An error always wins
// over the decision that came with it, so an allow that arrives together with
// an error is never used.
func (enforcer *Enforcer) decide(ctx context.Context, accessRequest model.AccessRequest) (model.Decision, error) {
	startedAt := enforcer.config.Now()
	decision, err := enforcer.config.Decider.Decide(ctx, accessRequest)
	decidedBy := decision.DecidedBy
	if err != nil {
		decidedBy = "error"
	}
	enforcer.decisionLatency.Observe(enforcer.config.Now().Sub(startedAt).Seconds(), "decided_by", decidedBy)
	if err != nil {
		return model.Decision{}, err
	}
	return decision, nil
}

// fulfilObligations carries out the duties the PDP attached to an allow. An
// obligation the PEP does not know makes the request fail: the PDP allowed it
// only on that condition.
func (enforcer *Enforcer) fulfilObligations(_ model.AccessRequest, decision model.Decision) error {
	// TODO(ztc): fulfil log, alert and reverify. Until then every obligation
	// is unknown, and the request is denied.
	if len(decision.Obligations) > 0 {
		return fmt.Errorf("unknown obligation %q", decision.Obligations[0])
	}
	return nil
}

// reportAuthentication sends an authentication signal for subject if none was
// sent in the last SignalInterval. It runs before the PDP is asked, so the
// very first request of a subject is decided with its authentication counted.
// A failed send is logged and does not stop the request: the PDP decides
// without the signal, or is down and the request gets 503 anyway.
func (enforcer *Enforcer) reportAuthentication(ctx context.Context, subject model.Subject) {
	strength, isKnownMethod := authenticationStrength[subject.AuthMethod]
	if enforcer.config.Signals == nil || !isKnownMethod {
		return
	}
	now := enforcer.config.Now()
	enforcer.mutex.Lock()
	lastReported, reportedBefore := enforcer.lastReported[subject.ID]
	isDue := !reportedBefore || now.Sub(lastReported) >= enforcer.config.SignalInterval
	if isDue {
		enforcer.lastReported[subject.ID] = now
	}
	enforcer.mutex.Unlock()
	if !isDue {
		return
	}
	signal := trust.Signal{Subject: subject.ID, Kind: trust.Authentication, Value: strength, Time: now, Source: enforcer.config.Name}
	if err := enforcer.config.Signals.RecordSignal(ctx, signal); err != nil {
		enforcer.config.Logger.Warn("authentication signal not sent", "pep", enforcer.config.Name, "subject", subject.ID, "reason", err)
	}
}

// reject counts outcome and answers with status and a short message.
func (enforcer *Enforcer) reject(writer http.ResponseWriter, outcome string, status int, message string) {
	enforcer.requests.Inc("outcome", outcome)
	http.Error(writer, message, status)
}

// logDecision logs a decision with everything an operator needs to find out
// why it was made.
func (enforcer *Enforcer) logDecision(message string, accessRequest model.AccessRequest, decision model.Decision) {
	enforcer.config.Logger.Info(message,
		"pep", enforcer.config.Name,
		"subject", accessRequest.Subject.ID,
		"action", accessRequest.Action,
		"resource", accessRequest.Resource.ID,
		"effect", decision.Effect,
		"rule", decision.RuleID,
		"reason", decision.Reason,
		"decidedBy", decision.DecidedBy,
		"trustScore", decision.TrustScore)
}
