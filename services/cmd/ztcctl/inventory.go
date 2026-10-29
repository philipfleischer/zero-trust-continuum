// The inventory commands of ztcctl: the master secret of the field devices,
// and the clients file of ztc-ca derived from the inventory.

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/inventory"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/token"
)

// caClient is one entry of the clients file of ztc-ca, in the format that
// ztc-ca's loadClients reads.
type caClient struct {
	SecretSHA256 string   `json:"secretSHA256"`
	Subject      string   `json:"subject"`
	Audience     []string `json:"audience"`
	Scope        []string `json:"scope,omitempty"`
	Roles        []string `json:"roles,omitempty"`
	Zone         string   `json:"zone,omitempty"`
}

// caClientsFile is the clients file of ztc-ca.
type caClientsFile struct {
	Clients []caClient `json:"clients"`
}

// inventoryCommand runs "ztcctl inventory secret" and "ztcctl inventory clients".
func inventoryCommand(arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) == 0 {
		return fmt.Errorf("%w: inventory needs the subcommand secret or clients", errUsage)
	}
	subcommand, subcommandArguments := arguments[0], arguments[1:]
	switch subcommand {
	case "secret":
		return makeMasterSecret(subcommandArguments, stderr)
	case "clients":
		return writeClientsFile(subcommandArguments, stdout, stderr)
	}
	return fmt.Errorf("%w: unknown subcommand inventory %s", errUsage, subcommand)
}

// makeMasterSecret writes a new random master secret to a file that only its
// owner can read.
func makeMasterSecret(arguments []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("ztcctl inventory secret", flag.ContinueOnError)
	flags.SetOutput(stderr)
	outputPath := flags.String("out", "", "new file for the master secret (required; must not exist)")
	if err := flags.Parse(arguments); err != nil {
		return parseError(err)
	}
	if *outputPath == "" {
		return fmt.Errorf("%w: inventory secret needs -out", errUsage)
	}
	masterSecret := make([]byte, inventory.MinMasterSecretSize)
	if _, err := rand.Read(masterSecret); err != nil {
		return err
	}
	return token.WriteSecretFile(*outputPath, masterSecret)
}

// writeClientsFile prints the clients file of ztc-ca for every device in the
// inventory. Each client gets the hash of its derived secret and the zone and
// roles from the inventory, so the CA vouches for exactly what the inventory
// says. The output holds hashes only, never a secret.
func writeClientsFile(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ztcctl inventory clients", flag.ContinueOnError)
	flags.SetOutput(stderr)
	inventoryPath := flags.String("inventory", "", "inventory file, such as deploy/inventory/substation.json (required)")
	masterSecretPath := flags.String("master-secret", "", "master secret file from inventory secret (required)")
	audience := flags.String("audience", "ztc-pep", "comma-separated services that accept the devices' tokens")
	scope := flags.String("scope", "telemetry:write", "comma-separated scopes of the devices' tokens")
	if err := flags.Parse(arguments); err != nil {
		return parseError(err)
	}
	if *inventoryPath == "" || *masterSecretPath == "" {
		return fmt.Errorf("%w: inventory clients needs -inventory and -master-secret", errUsage)
	}
	loaded, err := inventory.LoadFile(*inventoryPath)
	if err != nil {
		return err
	}
	masterSecret, err := token.ReadSecretFile(*masterSecretPath)
	if err != nil {
		return err
	}

	file := caClientsFile{Clients: []caClient{}}
	for _, device := range loaded.Devices {
		subjectID := loaded.SubjectID(device)
		secret, err := inventory.DeviceSecret(masterSecret, subjectID)
		if err != nil {
			return err
		}
		secretHash := sha256.Sum256([]byte(secret))
		file.Clients = append(file.Clients, caClient{
			SecretSHA256: hex.EncodeToString(secretHash[:]),
			Subject:      subjectID,
			Audience:     splitList(*audience),
			Scope:        splitList(*scope),
			Roles:        device.Roles,
			Zone:         device.Zone,
		})
	}
	if err := writeJSON(stdout, file); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stderr, "%d clients from %s\n", len(file.Clients), *inventoryPath)
	return err
}
