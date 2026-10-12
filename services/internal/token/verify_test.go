// Negative tests for Verify: every way an attacker or a broken issuer can get
// a token wrong, each rejected with its own error.

package token

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

// forgeToken signs any header and payload JSON with privateKey, so a test can
// build a token with a valid signature that Sign would never produce.
func forgeToken(privateKey ed25519.PrivateKey, headerJSON, payloadJSON string) string {
	signingInput := base64URL.EncodeToString([]byte(headerJSON)) + "." + base64URL.EncodeToString([]byte(payloadJSON))
	signature := ed25519.Sign(privateKey, []byte(signingInput))
	return signingInput + "." + base64URL.EncodeToString(signature)
}

func TestVerifyRejects(t *testing.T) {
	signer, verifier := newTestSigner(t)
	goodToken, err := signer.Sign(pmuClaims())
	if err != nil {
		t.Fatal(err)
	}
	goodParts := strings.Split(goodToken, ".")
	goodHeader, goodPayload, goodSignature := goodParts[0], goodParts[1], goodParts[2]

	// An attacker with their own key, using our kid.
	_, attackerKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signedByAttacker, err := (Signer{KeyID: "k1", Key: attackerKey}).Sign(pmuClaims())
	if err != nil {
		t.Fatal(err)
	}
	admin := pmuClaims()
	admin.Subject = "spiffe://grid.example/cloud/admin/mallory"
	adminToken, err := (Signer{KeyID: "k1", Key: attackerKey}).Sign(admin)
	if err != nil {
		t.Fatal(err)
	}
	adminPayload := strings.Split(adminToken, ".")[1]

	validPayload := `{"sub":"spiffe://grid.example/edge/pmu/1","aud":["ztc-pep"],"exp":1791806460,"jti":"jti-1"}`
	emptyAudiencePayload := `{"sub":"spiffe://grid.example/edge/pmu/1","aud":[""],"exp":1791806460,"jti":"jti-1"}`
	noExpiryPayload := `{"sub":"spiffe://grid.example/edge/pmu/1","aud":["ztc-pep"],"jti":"jti-1"}`
	clockAt := func(offset time.Duration) func(*Verifier) {
		return func(verifier *Verifier) { verifier.Now = func() time.Time { return referenceTime.Add(offset) } }
	}

	tests := []struct {
		name           string
		token          string
		changeVerifier func(*Verifier) // nil keeps the verifier from newTestSigner
		want           error
	}{
		// The header: the token must not choose how it is checked.
		{"alg none without signature", base64URL.EncodeToString([]byte(`{"alg":"none","typ":"ZTC","kid":"k1"}`)) + "." + goodPayload + ".", nil, ErrAlgorithm},
		{"alg none with valid signature", forgeToken(signer.Key, `{"alg":"none","typ":"ZTC","kid":"k1"}`, validPayload), nil, ErrAlgorithm},
		{"alg HS256", forgeToken(signer.Key, `{"alg":"HS256","typ":"ZTC","kid":"k1"}`, validPayload), nil, ErrAlgorithm},
		{"typ JWT", forgeToken(signer.Key, `{"alg":"EdDSA","typ":"JWT","kid":"k1"}`, validPayload), nil, ErrAlgorithm},
		{"unknown kid", forgeToken(signer.Key, `{"alg":"EdDSA","typ":"ZTC","kid":"k2"}`, validPayload), nil, ErrUnknownKey},
		{"public key of wrong length", goodToken, func(verifier *Verifier) { verifier.Keys = map[string]ed25519.PublicKey{"k1": make([]byte, 5)} }, ErrUnknownKey},

		// The signature: nobody without the private key can make or change a token.
		{"signed with another key", signedByAttacker, nil, ErrSignature},
		{"payload swapped", goodHeader + "." + adminPayload + "." + goodSignature, nil, ErrSignature},
		{"signature truncated", goodToken[:len(goodToken)-4], nil, ErrSignature},
		{"signature removed", goodHeader + "." + goodPayload + ".", nil, ErrSignature},

		// The format.
		{"empty", "", nil, ErrMalformed},
		{"two parts", goodHeader + "." + goodPayload, nil, ErrMalformed},
		{"four parts", goodToken + ".x", nil, ErrMalformed},
		{"header not base64url", "!!!." + goodPayload + "." + goodSignature, nil, ErrMalformed},
		{"header not JSON", base64URL.EncodeToString([]byte("EdDSA")) + "." + goodPayload + "." + goodSignature, nil, ErrMalformed},
		{"payload not JSON", forgeToken(signer.Key, `{"alg":"EdDSA","typ":"ZTC","kid":"k1"}`, "sub=x"), nil, ErrMalformed},
		{"too long", goodToken + strings.Repeat("A", MaxTokenSize), nil, ErrMalformed},

		// The claims and the time window.
		{"no expiry", forgeToken(signer.Key, `{"alg":"EdDSA","typ":"ZTC","kid":"k1"}`, noExpiryPayload), nil, ErrMissingClaim},
		{"at expiry", goodToken, clockAt(time.Minute), ErrExpired},
		{"long after expiry", goodToken, clockAt(time.Hour), ErrExpired},
		{"before not-before", goodToken, clockAt(-time.Second), ErrNotYetValid},
		{"wrong audience", goodToken, func(verifier *Verifier) { verifier.Audience = "ztc-historian" }, ErrAudience},
		{"verifier without audience", goodToken, func(verifier *Verifier) { verifier.Audience = "" }, ErrAudience},
		{"verifier without audience, token for empty audience", forgeToken(signer.Key, `{"alg":"EdDSA","typ":"ZTC","kid":"k1"}`, emptyAudiencePayload), func(verifier *Verifier) { verifier.Audience = "" }, ErrAudience},

		// What must still pass.
		{"one second before expiry", goodToken, clockAt(time.Minute - time.Second), nil},
		{"after expiry within leeway", goodToken, func(verifier *Verifier) { clockAt(time.Minute)(verifier); verifier.Leeway = 5 * time.Second }, nil},
		{"before not-before within leeway", goodToken, func(verifier *Verifier) { clockAt(-time.Second)(verifier); verifier.Leeway = 5 * time.Second }, nil},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			verifierUnderTest := verifier
			if testCase.changeVerifier != nil {
				testCase.changeVerifier(&verifierUnderTest)
			}
			got, err := verifierUnderTest.Verify(testCase.token)
			if !errors.Is(err, testCase.want) {
				t.Fatalf("Verify error %v, want %v", err, testCase.want)
			}
			if err != nil && got.Subject != "" {
				t.Errorf("Verify returned claims %+v together with an error", got)
			}
		})
	}
}
