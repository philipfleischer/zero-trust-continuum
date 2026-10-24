// The reverse proxy: what an allowed request looks like when it reaches the
// protected service.

package pep

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// Headers the PEP sets on every request it forwards, so the upstream knows
// who was allowed and by which rule.
const (
	SubjectHeader = "X-ZTC-Subject"
	RuleHeader    = "X-ZTC-Rule"
)

// NewProxy returns the whole PEP as one handler: the enforcer's middleware in
// front of a reverse proxy to the upstream of each request's route. transport
// reaches the upstreams; nil means http.DefaultTransport.
//
// Before a request is forwarded, the client's Authorization header and every
// X-ZTC-* header it sent are removed, and the PEP sets SubjectHeader and
// RuleHeader itself. The credential is for the PEP only, and an upstream can
// trust the X-ZTC-* headers because no client can set them.
func NewProxy(enforcer *Enforcer, transport http.RoundTripper) http.Handler {
	proxyByUpstream := make(map[string]*httputil.ReverseProxy)
	for _, route := range enforcer.config.Routes.routes {
		if _, exists := proxyByUpstream[route.Upstream]; exists {
			continue
		}
		upstream, _ := url.Parse(route.Upstream) // NewRouteTable has checked that it parses
		proxyByUpstream[route.Upstream] = &httputil.ReverseProxy{
			Rewrite:      rewriteFor(upstream),
			Transport:    transport,
			ErrorHandler: enforcer.upstreamFailed,
		}
	}
	forward := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		// The middleware matched the same path in the same table, so the
		// route is found; the check only guards against a future change.
		route, found := enforcer.config.Routes.Match(request.URL.Path)
		if !found {
			http.Error(writer, "no such resource", http.StatusNotFound)
			return
		}
		proxyByUpstream[route.Upstream].ServeHTTP(writer, request)
	})
	return enforcer.Middleware(forward)
}

// rewriteFor returns the function that turns an incoming request into the
// one sent to upstream.
func rewriteFor(upstream *url.URL) func(*httputil.ProxyRequest) {
	return func(proxyRequest *httputil.ProxyRequest) {
		proxyRequest.SetURL(upstream)
		proxyRequest.SetXForwarded()
		outgoing := proxyRequest.Out.Header
		outgoing.Del("Authorization")
		for name := range outgoing {
			if strings.HasPrefix(strings.ToLower(name), "x-ztc-") {
				outgoing.Del(name)
			}
		}
		if subject, found := SubjectFrom(proxyRequest.In.Context()); found {
			outgoing.Set(SubjectHeader, subject.ID)
		}
		if decision, found := DecisionFrom(proxyRequest.In.Context()); found {
			outgoing.Set(RuleHeader, decision.RuleID)
		}
	}
}

// upstreamFailed answers 502 when the upstream cannot be reached, and logs why.
func (enforcer *Enforcer) upstreamFailed(writer http.ResponseWriter, request *http.Request, err error) {
	enforcer.config.Logger.Error("upstream unavailable", "pep", enforcer.config.Name, "path", request.URL.Path, "reason", err)
	enforcer.config.Metrics.Counter("ztc_pep_upstream_errors_total", "Allowed requests the upstream did not answer.").Inc()
	http.Error(writer, "upstream unavailable", http.StatusBadGateway)
}
