// Obligations: the duties the PDP attaches to an allow, which the PEP must
// carry out before it forwards the request.

package pep

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

// ReverifyHeader tells the client how long it may reuse its authorization
// before it must authenticate again.
const ReverifyHeader = "X-ZTC-Reverify-After"

// obligation is one parsed obligation, ready to be carried out.
type obligation struct {
	kind     string // "log", "alert" or "reverify"
	argument string // the part after ":", e.g. "soc" or "10s"
}

// parseObligation checks one obligation of the form kind or kind:argument.
// The PEP knows three:
//
//	log             write an audit record of the allowed request
//	alert:<target>  the same record as a warning for target, e.g. "soc"
//	reverify:<d>    tell the client to authenticate again within duration d
//
// Anything else is an error, because the PDP allowed the request only on the
// condition that the obligation is carried out.
func parseObligation(text string) (obligation, error) {
	kind, argument, _ := strings.Cut(text, ":")
	switch kind {
	case "log":
		if argument == "" {
			return obligation{kind: kind}, nil
		}
	case "alert":
		if argument != "" {
			return obligation{kind: kind, argument: argument}, nil
		}
	case "reverify":
		interval, err := time.ParseDuration(argument)
		if err == nil && interval > 0 {
			return obligation{kind: kind, argument: argument}, nil
		}
	}
	return obligation{}, fmt.Errorf("obligation %q cannot be fulfilled", text)
}

// fulfilObligations carries out the obligations of an allow. All of them are
// checked before any is carried out, so a request with one obligation the PEP
// cannot fulfil leaves no audit record claiming that it was allowed.
func (enforcer *Enforcer) fulfilObligations(writer http.ResponseWriter, accessRequest model.AccessRequest, decision model.Decision) error {
	parsed := make([]obligation, 0, len(decision.Obligations))
	for _, text := range decision.Obligations {
		duty, err := parseObligation(text)
		if err != nil {
			return err
		}
		parsed = append(parsed, duty)
	}
	for _, duty := range parsed {
		switch duty.kind {
		case "log":
			enforcer.logDecision("request allowed", accessRequest, decision)
		case "alert":
			enforcer.config.Logger.Warn("alert",
				"target", duty.argument,
				"pep", enforcer.config.Name,
				"subject", accessRequest.Subject.ID,
				"action", accessRequest.Action,
				"resource", accessRequest.Resource.ID,
				"rule", decision.RuleID)
		case "reverify":
			writer.Header().Set(ReverifyHeader, duty.argument)
		}
	}
	return nil
}
