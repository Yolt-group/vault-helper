package main

import (
	"fmt"
	"path"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

func nexus(c *cli.Context) error {

	clt, err := getClient(c)
	if err != nil {
		return errors.Wrap(err, "failed to get vault client")
	}

	role := c.String("role")
	vaultPath := path.Join("nexus/issue", role)
	secret, err := clt.Logical().Read(vaultPath)
	if err != nil {
		return errors.Wrapf(err, "failed to read vault-path %q", vaultPath)
	} else if secret == nil {
		return nil
	}

	userId := secret.Data["user_id"].(string)
	password := secret.Data["password"].(string)
	ttl := secret.Data["ttl"].(string)

	roles := []string{}
	rolesRaw := secret.Data["roles"].([]interface{})
	for _, roleRaw := range rolesRaw {
		roles = append(roles, roleRaw.(string))
	}

	fmt.Printf("username:  %s\n", userId)
	fmt.Printf("password:  %s\n", password)
	fmt.Printf("ttl:       %s\n", ttl)
	fmt.Printf("roles:     %s\n", roles)

	return nil
}
