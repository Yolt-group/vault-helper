package main

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	oidc "github.com/hashicorp/vault-plugin-auth-jwt"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

type userInput interface {
	getRole() (string, error)
}

type userInputCmdline struct{}

func (in userInputCmdline) getRole() (string, error) {
	return getUserInputCmdline("Role: ")
}

func getUserInputCmdline(promptText string) (string, error) {
	fmt.Printf(promptText)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	err := scanner.Err()
	if err != nil {
		return "", err
	}
	x := scanner.Text()
	return x, nil
}

func getRole(c *cli.Context, state *State, in userInput) error {
	if c.String("role") != "" {
		state.Role = strings.ToLower(c.String("role"))
		fmt.Printf("Role: %s\n", state.Role)
		return nil
	}

	if state.Role != "" {
		fmt.Println("Role: " + state.Role)
		return nil
	}

	var err error
	state.Role, err = in.getRole()
	if err != nil {
		return errors.Wrap(err, "failed to scan role")
	}

	if state.Role == "" {
		return errors.New("Role can't be empty")
	}

	return nil
}

func login(c *cli.Context, l stateLoader, in userInputCmdline) error {

	client, err := getClient(c)
	if err != nil {
		return errors.Wrap(err, "failed to get vault client")
	}

	state, err := l.load()
	if err != nil {
		return errors.Wrap(err, "failed to load state")
	}

	config := api.DefaultConfig()
	if c.String("address") != "" {
		config.Address = c.String("address")
	}

	err = getRole(c, state, in)
	if err != nil {
		return err
	}

	// Authenticate delegation to the auth handler
	oidcHandler := &oidc.CLIHandler{}
	oidcData := map[string]string{
		"role":          "yolt",
		"listenaddress": "127.0.0.1",
		"port":          "8250",
	}

	secret, err := oidcHandler.Auth(client, oidcData)
	if err != nil {
		return errors.Wrap(err, "authentication error")
	}

	client.SetToken(secret.Auth.ClientToken)
	if err = verifyRole(client, state.Role); err != nil {
		return errors.Wrapf(err, "failed to verify role: %s", state.Role)
	}

	token := secret.Auth.ClientToken

	helper, err := newTokenHelper(c)
	if err != nil {
		return errors.Wrap(err, "failed to create token helper")
	}

	err = helper.Store(token)
	if err != nil {
		return errors.Wrap(err, "failed to store token")
	}

	statePath, err := getStatePath(c)
	if err != nil {
		return errors.Wrapf(err, "failed to get state path")
	}

	err = saveState(statePath, state)
	if err != nil {
		return errors.Wrap(err, "failed to save state")
	}

	fmt.Printf("Token stored, valid for: %s\n", time.Duration(secret.Auth.LeaseDuration)*time.Second)
	fmt.Println("Remember to run the following command within that time")
	fmt.Println("or your token and all certificates/secrets will expire!")
	fmt.Println("vault-helper renew")

	return nil
}

func verifyRole(clt *api.Client, role string) error {

	vaultPath := "/auth/token/lookup-self"
	secret, err := clt.Logical().Read(vaultPath)
	if err != nil {
		return errors.Wrapf(err, "failed to read: %s", vaultPath)
	}
	entityID := secret.Data["entity_id"].(string)

	vaultPath = path.Join("/identity/entity/id", entityID)
	secret, err = clt.Logical().Read(vaultPath)
	if err != nil {
		return errors.Wrapf(err, "failed to read path: %s", vaultPath)
	}

	groupIDs := secret.Data["group_ids"].([]interface{})
	found := false
	for _, id := range groupIDs {
		vaultPath = path.Join("/identity/group/id", id.(string))
		secret, err = clt.Logical().Read(vaultPath)
		if err != nil {
			return errors.Wrapf(err, "failed to read path: %s", vaultPath)
		}

		if metadataRaw, ok := secret.Data["metadata"]; ok {
			if metadata, ok := metadataRaw.(map[string]interface{}); ok {
				if primaryRoleRaw, ok := metadata["primaryRole"]; ok {
					if primaryRole, ok := primaryRoleRaw.(string); ok && primaryRole == role {
						found = true
						break
					}
				}
			}
		}
	}

	if !found {
		return errors.Errorf("role not found in any identity group with ID: %s", groupIDs)
	}

	return nil
}
