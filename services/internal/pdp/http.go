// The HTTP API of the PDP: decisions for PEPs, signals from PEPs and the IDS,
// and the administration of policy and emergency mode.

package pdp

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/httpx"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/observability"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/policy"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/trust"
)

// TrustResponse is the body of GET /v1/trust.
type TrustResponse struct {
	Subject string      `json:"subject"`
	Score   float64     `json:"score"`
	Level   trust.Level `json:"level"`
}

// EmergencyState is the body of GET and PUT /v1/emergency.
type EmergencyState struct {
	On bool `json:"on"`
}

// NewHandler returns the HTTP API of pdp:
//
//	POST /v1/decide              model.AccessRequest → model.Decision
//	POST /v1/signals             trust.Signal → 204                 (token)
//	GET  /v1/trust?subject=<id>  → TrustResponse
//	GET  /v1/policy              → policy.Policy
//	PUT  /v1/policy              policy.Policy → 204                (token)
//	GET  /v1/emergency           → EmergencyState
//	PUT  /v1/emergency           EmergencyState → 204               (token)
//
// Requests marked (token) change the PDP and need the header
// "Authorization: Bearer <token>". An empty token disables them. Decisions are
// counted in registry as ztc_pdp_decisions_total{effect}.
func NewHandler(pdp *PDP, token string, registry *observability.Registry) http.Handler {
	api := &pdpAPI{
		pdp:       pdp,
		token:     token,
		decisions: registry.Counter("ztc_pdp_decisions_total", "Access decisions by effect."),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/decide", api.decide)
	mux.HandleFunc("POST /v1/signals", api.requireToken(api.recordSignal))
	mux.HandleFunc("GET /v1/trust", api.getTrust)
	mux.HandleFunc("GET /v1/policy", api.getPolicy)
	mux.HandleFunc("PUT /v1/policy", api.requireToken(api.putPolicy))
	mux.HandleFunc("GET /v1/emergency", api.getEmergency)
	mux.HandleFunc("PUT /v1/emergency", api.requireToken(api.putEmergency))
	return mux
}

// pdpAPI holds what the endpoints share.
type pdpAPI struct {
	pdp       *PDP
	token     string
	decisions *observability.Counter
}

// requireToken wraps next so it runs only with the right bearer token. The
// comparison takes the same time however much of the token is right, so the
// token cannot be guessed one character at a time.
func (api *pdpAPI) requireToken(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if api.token == "" {
			httpx.Error(writer, http.StatusForbidden, "writes are disabled on this PDP")
			return
		}
		presentedToken, hasBearer := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
		tokenMatches := subtle.ConstantTimeCompare([]byte(presentedToken), []byte(api.token)) == 1
		if !hasBearer || !tokenMatches {
			writer.Header().Set("WWW-Authenticate", "Bearer")
			httpx.Error(writer, http.StatusUnauthorized, "missing or wrong bearer token")
			return
		}
		next(writer, request)
	}
}

func (api *pdpAPI) decide(writer http.ResponseWriter, request *http.Request) {
	var accessRequest model.AccessRequest
	if err := httpx.ReadJSON(writer, request, &accessRequest); err != nil {
		badRequest(writer, err)
		return
	}
	decision, err := api.pdp.Decide(request.Context(), accessRequest)
	api.decisions.Inc("effect", string(decision.Effect))
	if err != nil {
		httpx.Error(writer, http.StatusServiceUnavailable, err.Error())
		return
	}
	httpx.WriteJSON(writer, http.StatusOK, decision)
}

func (api *pdpAPI) recordSignal(writer http.ResponseWriter, request *http.Request) {
	var signal trust.Signal
	if err := httpx.ReadJSON(writer, request, &signal); err != nil {
		badRequest(writer, err)
		return
	}
	if _, err := api.pdp.RecordSignal(signal); err != nil {
		httpx.Error(writer, http.StatusBadRequest, err.Error())
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (api *pdpAPI) getTrust(writer http.ResponseWriter, request *http.Request) {
	subject := request.URL.Query().Get("subject")
	if subject == "" {
		httpx.Error(writer, http.StatusBadRequest, "missing query parameter subject")
		return
	}
	score := api.pdp.Trust.Score(subject)
	httpx.WriteJSON(writer, http.StatusOK, TrustResponse{Subject: subject, Score: score, Level: trust.LevelOf(score)})
}

func (api *pdpAPI) getPolicy(writer http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(writer, http.StatusOK, api.pdp.Engine.Policy())
}

func (api *pdpAPI) putPolicy(writer http.ResponseWriter, request *http.Request) {
	newPolicy, err := policy.Load(http.MaxBytesReader(writer, request.Body, httpx.MaxBody))
	if err != nil {
		badRequest(writer, err)
		return
	}
	if err := api.pdp.Engine.Install(newPolicy); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, policy.ErrStalePolicy) {
			status = http.StatusConflict
		}
		httpx.Error(writer, status, err.Error())
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (api *pdpAPI) getEmergency(writer http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(writer, http.StatusOK, EmergencyState{On: api.pdp.Emergency()})
}

func (api *pdpAPI) putEmergency(writer http.ResponseWriter, request *http.Request) {
	var emergency EmergencyState
	if err := httpx.ReadJSON(writer, request, &emergency); err != nil {
		badRequest(writer, err)
		return
	}
	api.pdp.SetEmergency(emergency.On)
	writer.WriteHeader(http.StatusNoContent)
}

// badRequest answers a body that could not be read: 413 if it was too large,
// 400 otherwise.
func badRequest(writer http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		status = http.StatusRequestEntityTooLarge
	}
	httpx.Error(writer, status, err.Error())
}
