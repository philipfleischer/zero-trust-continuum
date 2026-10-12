// Reading and writing policies as JSON, the format of deploy/policies/*.json
// and of the PDP's PUT /v1/policy.

package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Load reads exactly one JSON policy from input and validates it. Unknown fields
// and data after the policy are errors, so a misspelt field such as
// "sujbects" is reported instead of silently dropped.
func Load(input io.Reader) (*Policy, error) {
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()
	var loaded Policy
	if err := decoder.Decode(&loaded); err != nil {
		return nil, fmt.Errorf("policy: decode: %w", err)
	}
	if decoder.More() {
		return nil, errors.New("policy: unexpected data after the policy")
	}
	if err := Validate(&loaded); err != nil {
		return nil, err
	}
	return &loaded, nil
}

// LoadFile reads and validates the JSON policy in the file at path.
func LoadFile(path string) (*Policy, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }() // read-only, so a close error cannot lose data
	loaded, err := Load(file)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return loaded, nil
}

// Marshal returns policy as JSON indented by two spaces with a trailing newline.
// It is the canonical form of the policy files, so the same policy always
// gives the same bytes and a diff shows only real changes.
func Marshal(policy *Policy) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false) // keep "<" and ">" readable in descriptions
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(policy); err != nil {
		return nil, fmt.Errorf("policy: encode: %w", err)
	}
	return buffer.Bytes(), nil
}
