// Command ztcctl is the operator's command line tool for ZTC.
//
// Usage:
//
//	ztcctl policy default              print the built-in substation policy as JSON
//	ztcctl policy validate <file>      check a policy file the way ztc-pdp loads it
//	ztcctl decide [flags]              ask a PDP for a decision
//	ztcctl signal [flags]              send a trust signal to a PDP
//	ztcctl keys gen -out <file>        make an Ed25519 signing key
//	ztcctl token issue [flags]         sign a token with a key file
//	ztcctl token verify [flags]        verify a token read from standard input
//	ztcctl cap rootkey -out <file>     make a root key for capabilities
//	ztcctl cap mint [flags] [caveat]   mint a capability with a root key file
//	ztcctl cap attenuate <caveat>...   narrow a capability read from standard input
//	ztcctl cap show                    print a capability read from standard input
//	ztcctl inventory secret -out <file>  make a master secret for the field devices
//	ztcctl inventory clients [flags]   print the ztc-ca clients file for an inventory
//
// Run "ztcctl <command> <subcommand> -h" for the flags.
//
// Exit status: 0 success (for decide: allow), 3 deny or rejected token,
// 1 error, 2 wrong usage.
//
// Secrets never come from command-line arguments, which every user on the
// machine can see with ps and which end up in the shell history. Tokens and
// capabilities are read from standard input, keys from files that only their
// owner can read, and the PDP token from the environment.
//
// Environment:
//
//	ZTC_PDP_URL     PDP base URL (default http://localhost:8181)
//	ZTC_PDP_TOKEN   bearer token for signal
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/config"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/pdp"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/policy"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/trust"
)

// Exit codes.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
	exitDeny  = 3
)

const usage = `usage: ztcctl <command>

  policy default              print the built-in substation policy as JSON
  policy validate <file>      check a policy file the way ztc-pdp loads it
  decide [flags]              ask a PDP for a decision (ztcctl decide -h)
  signal [flags]              send a trust signal to a PDP (ztcctl signal -h)
  keys gen -out <file>        make an Ed25519 signing key
  token issue [flags]         sign a token (ztcctl token issue -h)
  token verify [flags]        verify a token from standard input
  cap rootkey -out <file>     make a root key for capabilities
  cap mint [flags] [caveat]   mint a capability (ztcctl cap mint -h)
  cap attenuate <caveat>...   narrow a capability from standard input
  cap show                    print a capability from standard input
  inventory secret -out <file>  make a master secret for the field devices
  inventory clients [flags]   print the ztc-ca clients file (ztcctl inventory clients -h)
`

var (
	// errUsage marks an error in how ztcctl was called.
	errUsage = errors.New("wrong usage")
	// errDenied is returned by decide when the PDP denies the request, and
	// by token verify when the token is rejected.
	errDenied = errors.New("denied")
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], config.New(), os.Stdin, os.Stdout, os.Stderr))
}

// run executes one ztcctl command and returns the exit status. It takes its
// dependencies as parameters so tests can call it directly.
func run(ctx context.Context, arguments []string, environment config.Env, stdin io.Reader, stdout, stderr io.Writer) int {
	err := dispatch(ctx, arguments, environment, stdin, stdout, stderr)
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, errDenied):
		return exitDeny
	case errors.Is(err, flag.ErrHelp):
		return exitOK
	case errors.Is(err, errUsage):
		_, _ = fmt.Fprintf(stderr, "ztcctl: %v\n\n%s", err, usage)
		return exitUsage
	default:
		_, _ = fmt.Fprintln(stderr, "ztcctl:", err)
		return exitError
	}
}

// dispatch picks the command named by the first arguments and runs it.
func dispatch(ctx context.Context, arguments []string, environment config.Env, stdin io.Reader, stdout, stderr io.Writer) error {
	pdpURL := environment.String("pdp_url", "http://localhost:8181")
	if len(arguments) == 0 {
		return fmt.Errorf("%w: no command", errUsage)
	}
	command, commandArguments := arguments[0], arguments[1:]
	switch {
	case command == "policy" && len(commandArguments) == 1 && commandArguments[0] == "default":
		return printDefaultPolicy(stdout)
	case command == "policy" && len(commandArguments) == 2 && commandArguments[0] == "validate":
		return validatePolicyFile(commandArguments[1], stdout)
	case command == "decide":
		return decideCommand(ctx, commandArguments, pdpURL, stdout, stderr)
	case command == "signal":
		return signalCommand(ctx, commandArguments, pdpURL, environment.String("pdp_token", ""), stderr)
	case command == "keys":
		return keysCommand(commandArguments, stdout, stderr)
	case command == "token":
		return tokenCommand(commandArguments, stdin, stdout, stderr)
	case command == "cap":
		return capabilityCommand(commandArguments, stdin, stdout, stderr)
	case command == "inventory":
		return inventoryCommand(commandArguments, stdout, stderr)
	}
	return fmt.Errorf("%w: unknown command %q", errUsage, strings.Join(arguments, " "))
}

// printDefaultPolicy writes the built-in policy in the canonical form of
// deploy/policies/substation.json.
func printDefaultPolicy(stdout io.Writer) error {
	data, err := policy.Marshal(policy.DefaultSubstationPolicy())
	if err != nil {
		return err
	}
	_, err = stdout.Write(data)
	return err
}

// validatePolicyFile loads the policy file at path the way ztc-pdp does and
// prints a one-line summary.
func validatePolicyFile(path string, stdout io.Writer) error {
	loaded, err := policy.LoadFile(path)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "ok: %s is policy version %d with %d rules\n", path, loaded.Version, len(loaded.Rules))
	return err
}

// decideCommand builds an access request from flags, asks the PDP and prints
// the decision. A deny returns errDenied, so scripts can test the exit status.
func decideCommand(ctx context.Context, arguments []string, pdpURL string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ztcctl decide", flag.ContinueOnError)
	flags.SetOutput(stderr)
	subject := flags.String("subject", "", "subject SPIFFE ID, e.g. spiffe://grid.example/edge/pmu/1 (required)")
	action := flags.String("action", "read", "action: read, write, operate, execute, migrate or admin")
	resource := flags.String("resource", "", "resource ID, e.g. bay-1/telemetry/pmu-1 (required)")
	resourceType := flags.String("type", "", "resource type, e.g. telemetry or breaker (required)")
	subjectZone := flags.String("zone", "", "the subject's zone")
	resourceZone := flags.String("resource-zone", "", "the resource's zone (default: -zone)")
	sourceZone := flags.String("source-zone", "", "the zone the request comes from (default: -zone)")
	roles := flags.String("roles", "", "comma-separated roles of the subject")
	if err := flags.Parse(arguments); err != nil {
		return parseError(err)
	}
	if *subject == "" || *resource == "" || *resourceType == "" {
		return fmt.Errorf("%w: decide needs -subject, -resource and -type", errUsage)
	}
	layer, err := layerOf(*subject)
	if err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	request := model.AccessRequest{
		Subject:  model.Subject{ID: *subject, Layer: layer, Zone: *subjectZone, Roles: splitList(*roles)},
		Action:   *action,
		Resource: model.Resource{ID: *resource, Type: *resourceType, Zone: valueOrDefault(*resourceZone, *subjectZone)},
		Context:  model.Context{SourceZone: valueOrDefault(*sourceZone, *subjectZone), SourceLayer: layer},
	}
	client := &pdp.RemoteClient{BaseURL: pdpURL, Timeout: 5 * time.Second}
	decision, err := client.Decide(ctx, request)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "%s: %s (trust %.3f, decided by %s)\n",
		decision.Effect, decision.Reason, decision.TrustScore, decision.DecidedBy)
	if err != nil {
		return err
	}
	if !decision.Allowed() {
		return errDenied
	}
	return nil
}

// signalCommand sends one trust signal, authenticated with ZTC_PDP_TOKEN.
func signalCommand(ctx context.Context, arguments []string, pdpURL, token string, stderr io.Writer) error {
	flags := flag.NewFlagSet("ztcctl signal", flag.ContinueOnError)
	flags.SetOutput(stderr)
	subject := flags.String("subject", "", "subject SPIFFE ID (required)")
	kind := flags.String("kind", "", "authentication, posture, behaviour, location, denial or compromise (required)")
	value := flags.Float64("value", 1, "signal value in [0, 1]")
	if err := flags.Parse(arguments); err != nil {
		return parseError(err)
	}
	signalKind := trust.Kind(*kind)
	if *subject == "" || !signalKind.Valid() {
		return fmt.Errorf("%w: signal needs -subject and a valid -kind", errUsage)
	}
	if token == "" {
		return errors.New("ZTC_PDP_TOKEN is not set")
	}
	client := &pdp.RemoteClient{BaseURL: pdpURL, Token: token, Timeout: 5 * time.Second}
	signal := trust.Signal{Subject: *subject, Kind: signalKind, Value: *value, Source: "ztcctl"}
	return client.RecordSignal(ctx, signal)
}

// layerOf reads the layer from a SPIFFE ID of the form
// spiffe://<trust-domain>/<layer>/<kind>/<name>.
func layerOf(spiffeID string) (model.Layer, error) {
	path, hasScheme := strings.CutPrefix(spiffeID, "spiffe://")
	segments := strings.Split(path, "/")
	if !hasScheme || len(segments) < 3 {
		return model.LayerUnknown, fmt.Errorf("subject %q is not of the form spiffe://<trust-domain>/<layer>/<kind>/<name>", spiffeID)
	}
	layerName := segments[1]
	return model.ParseLayer(layerName)
}

// splitList turns "operator, engineer" into ["operator" "engineer"] and drops
// empty items. It splits roles, audiences and scopes.
func splitList(commaSeparated string) []string {
	var items []string
	for _, item := range strings.Split(commaSeparated, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}

// valueOrDefault returns value, or defaultValue if value is empty.
func valueOrDefault(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}

// parseError keeps -h a success and turns other flag errors into usage errors.
func parseError(err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return err
	}
	return fmt.Errorf("%w: %w", errUsage, err)
}
