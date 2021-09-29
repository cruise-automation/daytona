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

func (a *AzureService) Auth(client *api.Client, config cfg.Config) (string, error) {
	metadata, err := a.getMetadata()
	if err != nil {
		return "", err
	}

	jwt, err := a.getJWT()
	if err != nil {
		return "", err
	}

	// https://www.vaultproject.io/api/auth/azure#login
	loginData := map[string]interface{}{
		"role":                config.VaultAuthRoleName,
		"subscription_id":     metadata.Compute.SubscriptionID,
		"vm_name":             metadata.Compute.Name,
		"vmss_name":           metadata.Compute.VMScalesetName,
		"resource_group_name": metadata.Compute.ResourceGroupName,
		"jwt":                 jwt,
	}

	return fetchVaultToken(client, config, loginData)
}

type simplifiedToken struct {
	AccessToken string `json:"access_token"`
}

func (a *AzureService) getJWT() (string, error) {
	url := "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

	token := new(simplifiedToken)

	if err := queryAzureMetadata(url, token); err != nil {
		return "", fmt.Errorf("error getting jwt: %w", err)
	}

	return token.AccessToken, nil
}

type simplifiedMetadata struct {
	Compute simplifiedCompute `json:"compute"`
}
type simplifiedCompute struct {
	Name              string `json:"name"`
	ResourceGroupName string `json:"resourceGroupName"`
	SubscriptionID    string `json:"subscriptionId"`
	VMScalesetName    string `json:"vmScaleSetName"`
}

func (a *AzureService) getMetadata() (*simplifiedMetadata, error) {
	url := "http://169.254.169.254/metadata/instance?format=json&api-version=2021-02-01"

	metadata := new(simplifiedMetadata)

	if err := queryAzureMetadata(url, metadata); err != nil {
		return nil, fmt.Errorf("error getting metadata: %w", err)
	}

	return metadata, nil
}

func queryAzureMetadata(url string, obj interface{}) error {
	r, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	r.Header.Add("Metadata", "true")

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code while querying Azure %d", resp.StatusCode)
	}

	err = json.NewDecoder(resp.Body).Decode(obj)

	return err
}
