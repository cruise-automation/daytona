/*
Copyright 2019 GM Cruise LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	cfg "github.com/cruise-automation/daytona/pkg/config"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault/api"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	iam "google.golang.org/api/iam/v1"
)

// GCPService is an external service that vault can authenticate requests against
type GCPService struct{}

// Auth is used to authenticate to the service
func (g *GCPService) Auth(client *api.Client, config cfg.Config) (string, error) {
	log.Info().Msg("attempting gcp iam auth..")
	if config.GCPServiceAccount == "" {
		return "", errors.New("-gcp-svc-acct is missing")
	}

	loginToken, err := g.getGCPSignedJwt(config.VaultAuthRoleName, config.GCPServiceAccount, "")
	if err != nil {
		return "", err
	}

	loginData := map[string]interface{}{
		"role": config.VaultAuthRoleName,
		"jwt":  loginToken,
	}
	return fetchVaultToken(client, config, loginData)
}

func (g *GCPService) getGCPSignedJwt(role, serviceAccount, project string) (string, error) {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, cleanhttp.DefaultClient())

	credentials, tokenSource, err := gcputil.FindCredentials("", ctx, iam.CloudPlatformScope)
	if err != nil {
		return "", fmt.Errorf("could not obtain credentials: %v", err)
	}

	httpClient := oauth2.NewClient(ctx, tokenSource)

	if serviceAccount == "" && credentials != nil {
		serviceAccount = credentials.ClientEmail
	}

	if serviceAccount == "" {
		return "", errors.New("could not obtain service account from credentials (are you using Application Default Credentials?). You must provide a service account to authenticate as")
	}

	if project == "" {
		project = "-"
		if credentials != nil {
			project = credentials.ProjectId
		}
	}

	var ttl = time.Duration(15) * time.Minute

	jwtPayload := map[string]interface{}{
		"aud": fmt.Sprintf("http://vault/%s", role),
		"sub": serviceAccount,
		"exp": time.Now().Add(ttl).Unix(),
	}
	payloadBytes, err := json.Marshal(jwtPayload)
	if err != nil {
		return "", fmt.Errorf("could not convert JWT payload to JSON string: %v", err)
	}

	jwtReq := &iam.SignJwtRequest{
		Payload: string(payloadBytes),
	}

	iamClient, err := iam.New(httpClient)
	if err != nil {
		return "", fmt.Errorf("could not create IAM client: %v", err)
	}

	resourceName := fmt.Sprintf("projects/%s/serviceAccounts/%s", project, serviceAccount)
	resp, err := iamClient.Projects.ServiceAccounts.SignJwt(resourceName, jwtReq).Do()
	if err != nil {
		return "", fmt.Errorf("unable to sign JWT for %s using given Vault credentials: %v", resourceName, err)
	}

	return resp.SignedJwt, nil
}
