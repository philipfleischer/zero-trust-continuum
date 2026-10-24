// The registered clients of ztc-ca: who may ask for a token, and what the
// token then says about them.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// registeredClient is one entry of the clients file. The CA, not the client,
// decides the subject, audience and scope of the tokens a client gets.
type registeredClient struct {
	// SecretSHA256 is the hex SHA-256 of the client's secret. The file never
	// holds the secret itself, so reading the file is not enough to get tokens.
	SecretSHA256 string   `json:"secretSHA256"`
	Subject      string   `json:"subject"`
	Audience     []string `json:"audience"`
	Scope        []string `json:"scope,omitempty"`
}

// clientsFile is the JSON format of ZTC_CA_CLIENTS_FILE.
type clientsFile struct {
	Clients []registeredClient `json:"clients"`
}

// loadClients reads the clients file at path and returns the clients by the
// hash of their secret. Every subject must be a SPIFFE ID in trustDomain,
// every client needs an audience, and a secret hash may appear only once.
// Unknown fields are errors, so a misspelt "scpoe" is not silently dropped.
func loadClients(path, trustDomain string) (map[string]registeredClient, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var file clientsFile
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if decoder.More() {
		return nil, fmt.Errorf("%s: unexpected data after the clients", path)
	}
	subjectPrefix := "spiffe://" + trustDomain + "/"
	clientsBySecretHash := make(map[string]registeredClient, len(file.Clients))
	for clientIndex, client := range file.Clients {
		if err := validateClient(client, subjectPrefix); err != nil {
			return nil, fmt.Errorf("%s: client %d: %w", path, clientIndex, err)
		}
		if _, duplicate := clientsBySecretHash[client.SecretSHA256]; duplicate {
			return nil, fmt.Errorf("%s: client %d: the same secret is registered twice", path, clientIndex)
		}
		clientsBySecretHash[client.SecretSHA256] = client
	}
	return clientsBySecretHash, nil
}

// validateClient reports the first mistake in one registered client.
func validateClient(client registeredClient, subjectPrefix string) error {
	hashBytes, err := hex.DecodeString(client.SecretSHA256)
	isLowercaseSHA256 := err == nil && len(hashBytes) == sha256.Size && client.SecretSHA256 == strings.ToLower(client.SecretSHA256)
	if !isLowercaseSHA256 {
		return errors.New("secretSHA256 must be 64 lowercase hex characters")
	}
	if client.SecretSHA256 == secretHash("") {
		return errors.New("secretSHA256 is the hash of an empty secret")
	}
	if !strings.HasPrefix(client.Subject, subjectPrefix) {
		return fmt.Errorf("subject %q is not in %s", client.Subject, subjectPrefix)
	}
	if len(client.Audience) == 0 {
		return errors.New("no audience")
	}
	return nil
}

// secretHash returns the hex SHA-256 of secret, the form it has in the
// clients file. It equals the output of: printf %s "$SECRET" | shasum -a 256
func secretHash(secret string) string {
	hash := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(hash[:])
}
