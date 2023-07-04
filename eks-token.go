package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	clientauthv1alpha1 "k8s.io/client-go/pkg/apis/clientauthentication/v1alpha1"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
)

// FIX DUPLICATE CODE!!
func eksToken(c *cli.Context) error {
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

	cluster := c.String("cluster")

	if !c.Bool("no-cache") {
		// read token from state
		if creds, ok := state.EKS["yolt-eks-"+cluster]; ok {
			time := time.Now().Add(10 * time.Second)
			if creds.Status.ExpirationTimestamp.Time.After(time) {
				response, err := json.Marshal(creds)
				if err != nil {
					return err
				}

				fmt.Printf(string(response))
				return nil
			}
		}
	}

	region := c.String("region")
	sess, err := session.NewSessionWithOptions(session.Options{
		Profile: "yolt-eks-" + cluster,
		Config: aws.Config{
			Region: aws.String(region),
		},
	})
	if err != nil {
		return errors.Wrapf(err, "failed to create AWS session")
	}

	eksSvc := eks.New(sess)
	_, eksErr := eksSvc.DescribeCluster(&eks.DescribeClusterInput{
		Name: &cluster,
	})

	// if describeCluster returns an error, our credentials are possibly not valid anymore
	if eksErr != nil {
		if err, ok := eksErr.(awserr.Error); ok {
			if err.Code() == eks.ErrCodeResourceNotFoundException {
				return errors.Wrapf(err, "eks cluster does not exist")
			}
		}
		// refresh aws credentials
		err := createOrUpdateEKSProfile(c, cluster, region, state.Role)

		if err != nil {
			return errors.Wrapf(err, "failed to refresh AWS credentials")
		}

		sess, err = session.NewSessionWithOptions(session.Options{
			Profile: "yolt-eks-" + cluster,
			Config: aws.Config{
				Region: aws.String(region),
			},
		})

		if err != nil {
			return errors.Wrapf(err, "failed to refresh AWS credentials")
		}
	}

	execCredentials, err := buildExecCredentials(&cluster, sess)

	if err != nil {
		return errors.Wrapf(err, "failed to build exec credentials")
	}

	execStruct := clientauthv1alpha1.ExecCredential{}
	err = json.Unmarshal([]byte(execCredentials), &execStruct)
	if err != nil {
		return errors.Wrapf(err, "failed to unmarshal exec credentials")
	}

	state.EKS["yolt-eks-"+cluster] = execStruct
	if err = saveState(statePath, state); err != nil {
		return errors.Wrapf(err, "failed to save state")
	}

	fmt.Printf(execCredentials)
	return nil
}

func buildExecCredentials(clusterName *string, sess *session.Session) (string, error) {
	gen, err := token.NewGenerator(true, false)
	if err != nil {
		return "", err
	}

	opts := &token.GetTokenOptions{
		ClusterID: aws.StringValue(clusterName),
		Session:   sess,
	}

	token, err := gen.GetWithOptions(opts)
	if err != nil {
		return "", err
	}

	return gen.FormatJSON(token), nil
}
