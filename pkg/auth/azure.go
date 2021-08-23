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

type simplifiedMetadata struct {
	Compute simplifiedCompute `json:"compute"`
}
type simplifiedCompute struct {
	Name              string `json:"name"`
	ResourceGroupName string `json:"resourceGroupName"`
	SubscriptionID    string `json:"subscriptionId"`
}

type simplifiedToken struct {
	AccessToken string `json:"access_token"`
}

func (a *AzureService) getJWT() (string, error) {
	// TODO: build the request in parts
	// response=$(curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F' -H Metadata:true -s)
	jwtEndpoint := "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
	r, err := http.NewRequest(http.MethodGet, jwtEndpoint, nil)
	if err != nil {
		return "", err
	}

	r.Header.Add("Metadata", "true")

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return "", err
	}

	token := new(simplifiedToken)
	err = json.NewDecoder(resp.Body).Decode(token)

	return token.AccessToken, err

}

func (a *AzureService) getMetadata() (*simplifiedMetadata, error) {
	// TODO: build the request in parts
	// Get metadata
	// Metadata is not exposed through the Azure-sdk-for-go https://github.com/Azure/azure-sdk-for-go/issues/982
	// metadata=$(curl -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2017-08-01")
	metadataEndpoint := "http://169.254.169.254/metadata/instance?api-version=2017-08-01"
	r, err := http.NewRequest(http.MethodGet, metadataEndpoint, nil)
	if err != nil {
		return nil, err
	}

	r.Header.Add("Metadata", "true")

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return nil, err
	}

	metadata := new(simplifiedMetadata)
	err = json.NewDecoder(resp.Body).Decode(metadata)

	return metadata, err
}
