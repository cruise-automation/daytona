/*
Copyright 2019-present, Cruise LLC

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
	"encoding/json"
	"fmt"
	"net/http"

	cfg "github.com/cruise-automation/daytona/pkg/config"
	"github.com/hashicorp/vault/api"
)

// AzureService is an external service that vault can authenticate request against
type AzureService struct{}

type azureVaultPayload struct {
	Role              string
	SubscriptionID    string
	VmName            string
	ResourceGroupName string
	JWT               string
}

func (a *AzureService) Auth(client *api.Client, config cfg.Config) (string, error) {
	metadata, err := a.getMetadata()
	if err != nil {
		return "", err
	}

	jwt, err := a.getJWT()
	if err != nil {
		return "", err
	}

	loginData := map[string]interface{}{
		"role":                config.VaultAuthRoleName,
		"subscription_id":     metadata.Compute.SubscriptionID,
		"vm_name":             metadata.Compute.Name,
		"resource_group_name": metadata.Compute.ResourceGroupName,
		"jwt":                 jwt,
	}

	return fetchVaultToken(client, config, loginData)
}

type simplifiedToken struct {
	AccessToken string `json:"access_token"`
}

func (a *AzureService) getJWT() (string, error) {
	r, err := http.NewRequest(http.MethodGet, "http://169.254.169.254/metadata/identity/oauth2/token", nil)
	if err != nil {
		return "", err
	}

	r.Header.Add("Metadata", "true")

	q := r.URL.Query()
	q.Add("format", "json")
	q.Add("api-version", "2018-02-01")
	q.Add("resource", "https://management.azure.com/")
	r.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code while getting JWT %d", resp.StatusCode)
	}

	token := new(simplifiedToken)
	err = json.NewDecoder(resp.Body).Decode(token)

	return token.AccessToken, err

}

type simplifiedMetadata struct {
	Compute simplifiedCompute `json:"compute"`
}
type simplifiedCompute struct {
	Name              string `json:"name"`
	ResourceGroupName string `json:"resourceGroupName"`
	SubscriptionID    string `json:"subscriptionId"`
}

func (a *AzureService) getMetadata() (*simplifiedMetadata, error) {
	r, err := http.NewRequest(http.MethodGet, "http://169.254.169.254/metadata/instance", nil)
	if err != nil {
		return nil, err
	}

	r.Header.Add("Metadata", "true")

	q := r.URL.Query()
	q.Add("format", "json")
	q.Add("api-version", "2017-08-01")
	r.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code while getting Metadata %d", resp.StatusCode)
	}

	metadata := new(simplifiedMetadata)
	err = json.NewDecoder(resp.Body).Decode(metadata)

	return metadata, err
}
