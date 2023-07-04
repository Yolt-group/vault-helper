package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

func awsAccount(c *cli.Context) error {

	client, err := getClient(c)
	if err != nil {
		return errors.Wrap(err, "failed to get vault client")
	}

	ttl := c.String("ttl")
	data := map[string]interface{}{
		"ttl": ttl,
	}

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

	role := "readonly-" + state.Role
	tfStateRole := "terraform-state-ro-"
	if c.Bool("rw") {
		role = state.Role
		tfStateRole = "terraform-state-rw-"
	}

	account := c.String("account")
	if c.String("tf-role") == "" {
		tfStateRole = tfStateRole + account
	} else {
		tfStateRole = tfStateRole + c.String("tf-role")
	}

	if c.String("role") != "" {
		role = c.String("role")
	}

	vaultPath := fmt.Sprintf("aws/sts/%s-%s", account, role)
	secret, err := client.Logical().Write(vaultPath, data)
	if err != nil {
		return errors.Wrapf(err, "failed to write to vault-path %q", vaultPath)
	}

	credsPath, err := getAWSCredsPath()
	if err != nil {
		return err
	}

	creds, err := newAWSCredentials(credsPath)
	if err != nil {
		return errors.Wrapf(err, "failed to create AWS credentials from %q", credsPath)
	}

	accessKey := secret.Data["access_key"].(string)
	secretKey := secret.Data["secret_key"].(string)
	sessionToken := secret.Data["security_token"].(string)

	signinURL, err := createSigninURL(accessKey, secretKey, sessionToken)
	if err != nil {
		return errors.Wrap(err, "failed to create signin URL")
	}

	p := awsProfile{header: "[yolt-" + account + "]",
		entries: []string{
			"aws_access_key_id = " + accessKey,
			"aws_secret_access_key = " + secretKey,
			"aws_session_token = " + sessionToken,
			"region = " + c.String("region"),
			"signin_url = " + signinURL,
			"sts_regional_endpoints = regional",
		}}

	stateProfileEntries := []string{
		"source_profile = yolt-" + account,
		"role_arn = arn:aws:iam::495023470469:role/" + tfStateRole,
		"role_session_name = " + tfStateRole + "-" + role,
		"duration_seconds = 3600",
	}

	stateProfile := awsProfile{header: "[yolt-state]",
		entries: stateProfileEntries,
	}

	stateProfileEnv := awsProfile{header: "[yolt-state-" + account + "]",
		entries: stateProfileEntries,
	}

	creds.setProfile(p)
	creds.setProfile(stateProfile)
	creds.setProfile(stateProfileEnv)

	if err = creds.store(); err != nil {
		return errors.Wrapf(err, "failed to store AWS credentials: %s", creds.path)
	}

	fmt.Printf("Signin URL:\n%s\n\n", signinURL)
	fmt.Printf("Credentials are added to profile %q in %s.\n", "yolt-"+account, credsPath)
	fmt.Printf("Credentials are valid for %s.\n", ttl)

	return nil
}

type awsProfile struct {
	header  string
	entries []string
}

type awsCredendials struct {
	path     string
	profiles []awsProfile
}

func newAWSCredentials(path string) (*awsCredendials, error) {
	creds := &awsCredendials{path: path,
		profiles: make([]awsProfile, 0, 5),
	}

	err := creds.load()
	if err != nil {
		return nil, errors.Wrap(err, "failed to load AWS credentials")
	}

	return creds, nil
}

func (c *awsCredendials) load() error {

	file, err := os.Open(c.path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	lines := make([]string, 0, 32)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return errors.Wrapf(err, "failed to scan file: %q", c.path)
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			c.profiles = append(c.profiles, awsProfile{
				header:  line,
				entries: make([]string, 0, 5),
			})

			continue
		}

		if len(c.profiles) == 0 {
			return errors.Errorf("bad aws credentials file: %s", c.path)
		}

		p := &c.profiles[len(c.profiles)-1]
		p.entries = append(p.entries, line)
	}

	return nil
}

func (c *awsCredendials) setProfile(profile awsProfile) {

	for i := range c.profiles {
		if c.profiles[i].header == profile.header {
			c.profiles[i] = profile
			return
		}
	}

	c.profiles = append(c.profiles, profile)
}

func (c *awsCredendials) store() error {

	b := bytes.NewBufferString("\n")
	for _, p := range c.profiles {
		b.WriteString(p.header)
		b.WriteByte('\n')
		for _, e := range p.entries {
			b.WriteString(e)
			b.WriteByte('\n')
		}
		b.WriteByte('\n')
	}

	return writeFile(c.path, b.String())
}

func createSigninURL(accessKey, secretKey, sessionToken string) (string, error) {

	const (
		issuerURL  = "https://yolt.signin.aws.amazon.com"
		consoleURL = "https://console.aws.amazon.com/ec2"
		signingURL = "https://signin.aws.amazon.com/federation"
	)

	data := struct {
		SessionID    string `json:"sessionId"`
		SessionKey   string `json:"sessionKey"`
		SessionToken string `json:"sessionToken"`
	}{
		accessKey,
		secretKey,
		sessionToken,
	}

	session, _ := json.Marshal(data)

	values := url.Values{}
	values.Add("Action", "getSigninToken")
	values.Add("DurationSeconds", "43200")
	values.Add("SessionType", "json")
	values.Add("Session", string(session))

	signingTokenURL := fmt.Sprintf("%s?%s", signingURL, values.Encode())
	resp, err := http.Get(signingTokenURL)
	if err != nil {
		return "", errors.Errorf("failed to call URL: %s", signingTokenURL)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Errorf("failed to read response body URL: %s", signingTokenURL)
	}

	token := struct {
		SigninToken string `json:"SigninToken"`
	}{}

	err = json.Unmarshal(body, &token)
	if err != nil {
		return "", errors.Wrap(err, "failed to unmashal response body")
	}

	values = url.Values{}
	values.Add("SigninToken", token.SigninToken)
	values.Add("Issuer", issuerURL)
	values.Add("Destination", consoleURL)
	values.Add("Action", "login")

	return fmt.Sprintf("%s?%s", signingURL, values.Encode()), nil
}

func getAWSCredsPath() (string, error) {
	homedir, _ := getHomeDir()
	dotPath := filepath.Join(homedir, ".aws")
	if _, err := os.Stat(dotPath); os.IsNotExist(err) {
		err = os.MkdirAll(dotPath, 0700)
		if err != nil {
			return "", errors.Wrapf(err, "failed to make dir %q", dotPath)
		}
	}

	credsPath := filepath.Join(dotPath, "credentials")
	if _, err := os.Stat(credsPath); os.IsNotExist(err) {
		file, err := os.OpenFile(credsPath, os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return "", errors.Wrapf(err, "failed to create file %q", credsPath)
		}
		file.Close()
	}

	return credsPath, nil
}
