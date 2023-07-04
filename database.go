package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

func database(c *cli.Context, dbType string) error {

	client, err := getClient(c)
	if err != nil {
		return errors.Wrap(err, "failed to get vault client")
	}

	role := c.String("role")
	if role == "" {

		statePath, err := getStatePath(c)
		if err != nil {
			return errors.Wrapf(err, "failed to get state path")
		}

		r := stateFileReader{statePath: statePath}
		state, err := loadState(r)
		if err != nil {
			return errors.Wrap(err, "failed to load state")
		}

		if state.Role == "" {
			return errors.New("failed to get role from state file, please run 'vault-helper login' first")
		}

		role = state.Role
	}

	env := c.String("env")
	instance := c.String("instance")
	rw := c.Bool("rw")
	vaultPath := vaultPathBuilder(env, dbType, role, instance, rw)

	secret, err := client.Logical().Read(vaultPath)
	if err != nil {
		return errors.Wrapf(err, "failed to read vault-path %q", vaultPath)
	} else if secret == nil {
		return errors.Errorf("no secret (does role %q exist?)", role)
	}

	format := c.String("format")
	switch format {
	case "env":
		switch dbType {
		case "rds":
			// to use with psql (example: docker run --env-file /tmp/rds --net=host --dns=172.17.0.2 -it postgres:alpine psql postgres)
			t := fmt.Sprintf("PGUSER=%s\nPGPASSWORD=%s\nPGHOST=%s.%s.yolt.io\nPGSSLMODE=require\n", secret.Data["username"], secret.Data["password"], rdsPrefix(instance), env)
			writeFile(c.String("path"), t)
		case "elasticsearch":
			// to use with curl (example: curl --netrc-file /tmp/elasticsearch "https://elasticsearch.${ENV}.yolt.io:9200/_cat/nodes?h=n,cpu,u,ip,du,dt,v")
			t := fmt.Sprintf("machine elasticsearch.%s.yolt.io login %s password %s\n", env, secret.Data["username"], secret.Data["password"])
			writeFile(c.String("path"), t)
		default:
			fmt.Printf("USERNAME=%s\n", secret.Data["username"])
			fmt.Printf("PASSWORD=%s\n", secret.Data["password"])
			fmt.Printf("TTL=%s\n", time.Duration(secret.LeaseDuration)*time.Second)
			fmt.Printf("LEASE_ID=%s\n", secret.LeaseID)
		}
	case "json":
		res := struct {
			Username string `json:"username"`
			Password string `json:"password"`
			TTL      string `json:"ttl"`
			LeaseID  string `json:"leaseID"`
		}{
			secret.Data["username"].(string),
			secret.Data["password"].(string),
			fmt.Sprintf("%s", time.Duration(secret.LeaseDuration)*time.Second),
			secret.LeaseID,
		}
		out, _ := json.Marshal(res)
		fmt.Printf("%s\n", out)
	default:
		fmt.Printf("Username: %s\n", secret.Data["username"])
		fmt.Printf("Password: %s\n", secret.Data["password"])
		fmt.Printf("TTL: %s\n", time.Duration(secret.LeaseDuration)*time.Second)
		fmt.Printf("Lease ID: %s\n", secret.LeaseID)
	}

	return nil
}

func vaultPathBuilder(env, dbType, role, instance string, rw bool) string {
	if dbType == "rds" {
		path := fmt.Sprintf("%s/database/%s/creds/%s", env, instance, role)
		if !rw {
			path = fmt.Sprintf("%s-ro", path)
		}
		return path
	}
	return fmt.Sprintf("%s/database/%s/creds/%s", env, dbType, role)
}

func rdsPrefix(i string) string {
	if i != "rds" {
		return fmt.Sprintf("rds-%s", i)
	}
	return "rds"
}
