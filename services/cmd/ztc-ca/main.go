// Command ztc-ca is the token service of ZTC, version 1: it issues signed
// tokens to registered clients and publishes the public key that verifies
// them. X.509 certificates for mutual TLS come to the same service in M5.
//
// API:
//
//	POST /v1/token   with "Authorization: Bearer <client secret>"
//	                 → {"token": "...", "expiresAt": "..."}
//	GET  /v1/keys    → the JSON Web Key Set of the signing key
//
// The token's subject, audience and scope come from the clients file, never
// from the request, so a client cannot ask for more than it was given.
//
// Environment:
//
//	ZTC_LISTEN            address to listen on (default :8090)
//	ZTC_LOG_LEVEL         debug, info, warn or error (default info)
//	ZTC_CA_KEY_FILE       signing key from "ztcctl keys gen" (required)
//	ZTC_CA_CLIENTS_FILE   registered clients as JSON; if unset, no client
//	                      gets a token
//	ZTC_TRUST_DOMAIN      SPIFFE trust domain of the subjects (default grid.example)
//	ZTC_TOKEN_TTL         lifetime of issued tokens (default 5m, at most 1h)
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/config"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/httpx"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/observability"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/svc"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/token"
)

// issuerName is the iss claim of every token from this service.
const issuerName = "ztc-ca"

// maxTokenLifetime is the longest ZTC_TOKEN_TTL accepted. Short-lived tokens
// limit what a stolen token is worth and how long a revocation list must
// remember it.
const maxTokenLifetime = time.Hour

func main() {
	// Cancel the context on Ctrl+C (SIGINT) or when Docker or Kubernetes
	// stops the container (SIGTERM), so the server shuts down gracefully.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, config.New(), os.Stdout)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ztc-ca:", err)
		os.Exit(1)
	}
}

// run starts the CA and blocks until ctx is cancelled or the server fails.
// It takes its dependencies as parameters so tests can call it directly.
func run(ctx context.Context, environment config.Env, logOutput io.Writer) error {
	service, err := svc.New("ztc-ca", environment, logOutput)
	if err != nil {
		return err
	}
	app, err := setup(environment, service)
	if err != nil {
		return err
	}
	return service.Serve(ctx, ":8090", app, nil)
}

// setup loads the signing key and the clients from the configuration and
// returns the HTTP API. A missing or unreadable key is an error: the CA never
// makes up a key of its own, because tokens signed with a key nobody else
// knows could not be verified, and would all become invalid on the next start.
func setup(environment config.Env, service *svc.Service) (http.Handler, error) {
	keyPath := environment.String("ca_key_file", "")
	if keyPath == "" {
		return nil, errors.New("ZTC_CA_KEY_FILE is not set; create a key with: ztcctl keys gen -out <file>")
	}
	privateKey, err := token.LoadPrivateKeyFile(keyPath)
	if err != nil {
		return nil, err
	}
	lifetime := environment.Duration("token_ttl", 5*time.Minute)
	if lifetime <= 0 || lifetime > maxTokenLifetime {
		return nil, fmt.Errorf("ZTC_TOKEN_TTL is %v, want above 0 and at most %v", lifetime, maxTokenLifetime)
	}
	trustDomain := environment.String("trust_domain", "grid.example")

	clients := map[string]registeredClient{}
	if clientsPath := environment.String("ca_clients_file", ""); clientsPath != "" {
		clients, err = loadClients(clientsPath, trustDomain)
		if err != nil {
			return nil, err
		}
	} else {
		service.Logger.Warn("ZTC_CA_CLIENTS_FILE is not set: no client can get a token")
	}

	publicKey := privateKey.Public().(ed25519.PublicKey) // always true for an Ed25519 private key
	issuer := &tokenIssuer{
		signer:        token.Signer{KeyID: token.KeyIDOf(publicKey), Key: privateKey},
		keySet:        token.JSONWebKeySet{Keys: []token.JSONWebKey{token.NewJSONWebKey(publicKey)}},
		clients:       clients,
		lifetime:      lifetime,
		now:           time.Now,
		logger:        service.Logger,
		tokenRequests: service.Metrics.Counter("ztc_ca_token_requests_total", "Token requests by result."),
	}
	service.Logger.Info("signing key loaded", "keyID", issuer.signer.KeyID, "clients", len(clients), "tokenTTL", lifetime.String())

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/token", issuer.issueToken)
	mux.HandleFunc("GET /v1/keys", issuer.publishKeys)
	return mux, nil
}

// tokenIssuer holds what the two endpoints share.
type tokenIssuer struct {
	signer        token.Signer
	keySet        token.JSONWebKeySet
	clients       map[string]registeredClient // by secretHash of the client secret
	lifetime      time.Duration
	now           func() time.Time
	logger        *slog.Logger
	tokenRequests *observability.Counter
}

// tokenResponse is the body of a successful POST /v1/token.
type tokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// issueToken answers POST /v1/token. The client proves who it is with its
// secret; the token then carries the subject, audience and scope registered
// for that secret, whatever the request body says.
func (issuer *tokenIssuer) issueToken(writer http.ResponseWriter, request *http.Request) {
	presentedSecret, hasBearer := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
	client, isRegistered := issuer.clients[secretHash(presentedSecret)]
	if !hasBearer || presentedSecret == "" || !isRegistered {
		issuer.tokenRequests.Inc("result", "unauthorized")
		writer.Header().Set("WWW-Authenticate", "Bearer")
		httpx.Error(writer, http.StatusUnauthorized, "missing or unknown client secret")
		return
	}

	now := issuer.now()
	// Whole seconds, because exp is in Unix seconds and the response must match it.
	expiresAt := now.Add(issuer.lifetime).Truncate(time.Second).UTC()
	claims := token.Claims{
		Issuer:    issuerName,
		Subject:   client.Subject,
		Audience:  client.Audience,
		ExpiresAt: expiresAt.Unix(),
		NotBefore: now.Unix(),
		IssuedAt:  now.Unix(),
		ID:        token.NewTokenID(),
		Scope:     client.Scope,
	}
	signedToken, err := issuer.signer.Sign(claims)
	if err != nil {
		issuer.tokenRequests.Inc("result", "error")
		httpx.Error(writer, http.StatusInternalServerError, "could not sign the token")
		return
	}
	issuer.tokenRequests.Inc("result", "issued")
	// Log the token ID, never the token: anyone who reads the log could use it.
	issuer.logger.Info("issued token", "subject", claims.Subject, "jti", claims.ID, "expiresAt", expiresAt)
	httpx.WriteJSON(writer, http.StatusOK, tokenResponse{Token: signedToken, ExpiresAt: expiresAt})
}

// publishKeys answers GET /v1/keys with the key set. Verifiers may cache it
// for five minutes.
func (issuer *tokenIssuer) publishKeys(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Cache-Control", "public, max-age=300")
	httpx.WriteJSON(writer, http.StatusOK, issuer.keySet)
}
