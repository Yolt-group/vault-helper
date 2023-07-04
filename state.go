package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Masterminds/semver"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	clientauthv1alpha1 "k8s.io/client-go/pkg/apis/clientauthentication/v1alpha1"
)

type State struct {
	HelperVersion string
	Certificates  map[string]CertificateState
	EKS           map[string]clientauthv1alpha1.ExecCredential
	Username      string
	Role          string
}

func newState() *State {

	return &State{
		HelperVersion: version,
		Certificates:  map[string]CertificateState{},
		EKS:           map[string]clientauthv1alpha1.ExecCredential{},
	}
}

type CertificateState struct {
	Paths     CertificatePaths
	VaultPath string
	CN        string
	Serial    string
	Expiry    time.Time
}

type stateReader interface {
	read() (string, error)
}

type stateFileReader struct {
	statePath string
}

func (r stateFileReader) read() (string, error) {
	data, err := ioutil.ReadFile(r.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}

	return string(data), err
}

type stateLoader interface {
	load() (*State, error)
}

type stateFileLoader struct {
	statePath string
}

func (l stateFileLoader) load() (*State, error) {
	return loadState(stateFileReader{statePath: l.statePath})
}

func getStatePath(ctx *cli.Context) (string, error) {
	configPath, err := getConfigPath(ctx)
	if err != nil {
		return "", errors.Wrap(err, "failed to get state path")
	}

	return filepath.Join(configPath, "state"), nil
}

func loadState(r stateReader) (*State, error) {

	content, err := r.read()
	if err != nil {
		return nil, errors.Wrap(err, "failed to read state file")
	}

	if err != nil {
		if os.IsNotExist(err) {
			return &State{
				Certificates: map[string]CertificateState{},
			}, nil
		}
		return nil, err
	}

	state := newState()
	if content != "" {
		stateData := []byte(content)
		err = json.Unmarshal(stateData, state)
		if err != nil {
			return nil, err
		}
	}

	str := fmt.Sprintf(">= %s", minStateVersion)
	svc, err := semver.NewConstraint(str)
	if err != nil {
		return nil, errors.Errorf("failed to parse minimal SemVer constraint: %q", str)
	}

	if !svc.Check(semver.MustParse(state.HelperVersion)) {
		sb := strings.Builder{}
		sb.WriteString("incompatible vault-helper state file: \n")
		sb.WriteString("  required: >= " + minStateVersion + "\n")
		sb.WriteString("  actual:   " + state.HelperVersion + "\n")
		sb.WriteString("delete state and try again\n")
		return nil, errors.New(sb.String())
	}

	return state, nil
}

func saveState(statePath string, state *State) error {
	configPath, _ := filepath.Split(statePath)
	err := os.MkdirAll(configPath, os.ModePerm)
	if err != nil {
		return errors.Wrapf(err, "failed to make dir: %s", configPath)
	}

	state.HelperVersion = version
	stateData, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return errors.Wrap(err, "failed to marshal json")
	}

	return ioutil.WriteFile(statePath, stateData, 0600)
}
