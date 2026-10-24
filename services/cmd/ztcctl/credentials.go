// The credential commands of ztcctl: Ed25519 signing keys, signed tokens and
// capabilities.

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/token"
)

// maxTokenLifetime is the longest -ttl token issue accepts. A long-lived
// bearer token is exactly what revocation lists exist to clean up after.
const maxTokenLifetime = 24 * time.Hour

// rootKeySize is the size of a new capability root key, in bytes.
const rootKeySize = 32

// keysCommand runs "ztcctl keys gen".
func keysCommand(arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "gen" {
		return fmt.Errorf("%w: keys needs the subcommand gen", errUsage)
	}
	flags := flag.NewFlagSet("ztcctl keys gen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	outputPath := flags.String("out", "", "new file for the private key (required; must not exist)")
	if err := flags.Parse(arguments[1:]); err != nil {
		return parseError(err)
	}
	if *outputPath == "" {
		return fmt.Errorf("%w: keys gen needs -out", errUsage)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := token.WritePrivateKeyFile(*outputPath, privateKey); err != nil {
		return err
	}
	publicPEM, err := token.EncodePublicKeyPEM(publicKey)
	if err != nil {
		return err
	}
	if _, err := stdout.Write(publicPEM); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stderr, "wrote %s, key ID %s\n", *outputPath, token.KeyIDOf(publicKey))
	return err
}

// tokenCommand runs "ztcctl token issue" and "ztcctl token verify".
func tokenCommand(arguments []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(arguments) == 0 {
		return fmt.Errorf("%w: token needs the subcommand issue or verify", errUsage)
	}
	subcommand, subcommandArguments := arguments[0], arguments[1:]
	switch subcommand {
	case "issue":
		return issueToken(subcommandArguments, stdout, stderr)
	case "verify":
		return verifyToken(subcommandArguments, stdin, stdout, stderr)
	}
	return fmt.Errorf("%w: unknown subcommand token %s", errUsage, subcommand)
}

// issueToken signs a token with the private key in -key and prints it.
func issueToken(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ztcctl token issue", flag.ContinueOnError)
	flags.SetOutput(stderr)
	keyPath := flags.String("key", "", "private key file from keys gen (required)")
	subject := flags.String("subject", "", "SPIFFE ID of the holder (required)")
	audience := flags.String("audience", "", "comma-separated services that may accept the token (required)")
	scope := flags.String("scope", "", "comma-separated scopes, e.g. telemetry:write")
	roles := flags.String("roles", "", "comma-separated roles, e.g. operator")
	zone := flags.String("zone", "", "the subject's zone, e.g. bay-1")
	issuer := flags.String("issuer", "ztcctl", "the iss claim")
	lifetime := flags.Duration("ttl", 5*time.Minute, "how long the token is valid, at most 24h")
	if err := flags.Parse(arguments); err != nil {
		return parseError(err)
	}
	if *keyPath == "" || *subject == "" || *audience == "" {
		return fmt.Errorf("%w: token issue needs -key, -subject and -audience", errUsage)
	}
	if *lifetime <= 0 || *lifetime > maxTokenLifetime {
		return fmt.Errorf("%w: -ttl must be above 0 and at most %v", errUsage, maxTokenLifetime)
	}
	privateKey, err := token.LoadPrivateKeyFile(*keyPath)
	if err != nil {
		return err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey) // always true for an Ed25519 private key
	now := time.Now()
	claims := token.Claims{
		Issuer:    *issuer,
		Subject:   *subject,
		Audience:  splitList(*audience),
		ExpiresAt: now.Add(*lifetime).Unix(),
		NotBefore: now.Unix(),
		IssuedAt:  now.Unix(),
		ID:        token.NewTokenID(),
		Scope:     splitList(*scope),
		Roles:     splitList(*roles),
		Zone:      *zone,
	}
	signer := token.Signer{KeyID: token.KeyIDOf(publicKey), Key: privateKey}
	signedToken, err := signer.Sign(claims)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, signedToken)
	return err
}

// verifyToken checks the token on standard input against the public key in
// -pub and prints its claims. A rejected token returns errDenied.
func verifyToken(arguments []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ztcctl token verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	publicKeyPath := flags.String("pub", "", "public key file, the output of keys gen (required)")
	audience := flags.String("audience", "", "the service that checks the token (required)")
	if err := flags.Parse(arguments); err != nil {
		return parseError(err)
	}
	if *publicKeyPath == "" || *audience == "" {
		return fmt.Errorf("%w: token verify needs -pub and -audience", errUsage)
	}
	publicPEM, err := os.ReadFile(filepath.Clean(*publicKeyPath))
	if err != nil {
		return err
	}
	publicKey, err := token.ParsePublicKeyPEM(publicPEM)
	if err != nil {
		return err
	}
	signedToken, err := readCredential(stdin)
	if err != nil {
		return err
	}
	verifier := token.Verifier{
		Keys:     map[string]ed25519.PublicKey{token.KeyIDOf(publicKey): publicKey},
		Audience: *audience,
	}
	claims, err := verifier.Verify(signedToken)
	if err != nil {
		_, _ = fmt.Fprintln(stdout, "rejected:", err)
		return errDenied
	}
	return writeJSON(stdout, claims)
}

// capabilityCommand runs "ztcctl cap rootkey", "mint", "attenuate" and "show".
func capabilityCommand(arguments []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(arguments) == 0 {
		return fmt.Errorf("%w: cap needs the subcommand rootkey, mint, attenuate or show", errUsage)
	}
	subcommand, subcommandArguments := arguments[0], arguments[1:]
	switch subcommand {
	case "rootkey":
		return makeRootKey(subcommandArguments, stderr)
	case "mint":
		return mintCapability(subcommandArguments, stdout, stderr)
	case "attenuate":
		return attenuateCapability(subcommandArguments, stdin, stdout)
	case "show":
		return showCapability(stdin, stdout)
	}
	return fmt.Errorf("%w: unknown subcommand cap %s", errUsage, subcommand)
}

// makeRootKey writes 32 random bytes to a new file that only its owner can read.
func makeRootKey(arguments []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("ztcctl cap rootkey", flag.ContinueOnError)
	flags.SetOutput(stderr)
	outputPath := flags.String("out", "", "new file for the root key (required; must not exist)")
	if err := flags.Parse(arguments); err != nil {
		return parseError(err)
	}
	if *outputPath == "" {
		return fmt.Errorf("%w: cap rootkey needs -out", errUsage)
	}
	rootKey := make([]byte, rootKeySize)
	if _, err := rand.Read(rootKey); err != nil {
		return err
	}
	return token.WriteSecretFile(*outputPath, rootKey)
}

// mintCapability mints a capability with the root key in -root-key, adds the
// caveats given as arguments, and prints it.
func mintCapability(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ztcctl cap mint", flag.ContinueOnError)
	flags.SetOutput(stderr)
	rootKeyPath := flags.String("root-key", "", "root key file from cap rootkey (required)")
	grantID := flags.String("id", "", "ID of the grant, e.g. grant-42 (required)")
	location := flags.String("location", "ztc-pdp", "the service that verifies the capability")
	if err := flags.Parse(arguments); err != nil {
		return parseError(err)
	}
	if *rootKeyPath == "" || *grantID == "" {
		return fmt.Errorf("%w: cap mint needs -root-key and -id", errUsage)
	}
	rootKey, err := token.ReadSecretFile(*rootKeyPath)
	if err != nil {
		return err
	}
	capability, err := token.NewCapability(rootKey, *grantID, *location)
	if err != nil {
		return err
	}
	for _, caveat := range flags.Args() {
		capability = capability.Attenuate(caveat)
	}
	_, err = fmt.Fprintln(stdout, capability.Encode())
	return err
}

// attenuateCapability adds the caveats given as arguments to the capability
// on standard input and prints the narrower capability.
func attenuateCapability(caveats []string, stdin io.Reader, stdout io.Writer) error {
	if len(caveats) == 0 {
		return fmt.Errorf("%w: cap attenuate needs at least one caveat", errUsage)
	}
	capability, err := readCapability(stdin)
	if err != nil {
		return err
	}
	for _, caveat := range caveats {
		capability = capability.Attenuate(caveat)
	}
	_, err = fmt.Fprintln(stdout, capability.Encode())
	return err
}

// showCapability prints the grant, location and caveats of the capability on
// standard input. It cannot check the signature: only the root key can.
func showCapability(stdin io.Reader, stdout io.Writer) error {
	capability, err := readCapability(stdin)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "grant %s, verified by %s, %d caveats (signature not checked)\n",
		capability.ID, capability.Location, len(capability.Caveats))
	if err != nil {
		return err
	}
	for _, caveat := range capability.Caveats {
		if _, err := fmt.Fprintln(stdout, "  "+caveat); err != nil {
			return err
		}
	}
	return nil
}

// readCapability decodes the capability on standard input.
func readCapability(stdin io.Reader) (token.Capability, error) {
	encoded, err := readCredential(stdin)
	if err != nil {
		return token.Capability{}, err
	}
	return token.DecodeCapability(encoded)
}

// readCredential reads one token or capability from standard input, with
// surrounding white space removed. Reading stops after MaxTokenSize + 1
// bytes, so the decoder still sees that the input was too long.
func readCredential(stdin io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(stdin, token.MaxTokenSize+1))
	if err != nil {
		return "", err
	}
	credential := strings.TrimSpace(string(data))
	if credential == "" {
		return "", fmt.Errorf("%w: expected a token or capability on standard input", errUsage)
	}
	return credential, nil
}

// writeJSON prints value as indented JSON.
func writeJSON(stdout io.Writer, value any) error {
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
