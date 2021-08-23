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
}

type azureVaultPayload struct {
	Role              string
	SubscriptionID    string
	VmName            string
	ResourceGroupName string
	JWT               string
}

type simplifiedMetadata struct {
	Compute simplifiedCompute `json:"compute"`
}
type simplifiedCompute struct {
	Name              string `json:"name"`
	ResourceGroupName string `json:"resourceGroupName"`
	SubscriptionID    string `json:"subscriptionId"`
}

func (a *AWSService) getJWT()(string, error) {
	// response=$(curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F' -H Metadata:true -s)
	jwt 
}

func (a *AWSService) getMetadata(baseURL string) (*simplifiedMetadata, error) {
	// Get metadata
	// Metadata is not exposed through the Azure-sdk-for-go https://github.com/Azure/azure-sdk-for-go/issues/982
	// metadata=$(curl -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2017-08-01")
	metadataEndpoint := fmt.Sprintf("%s/metadata/instance?api-version=2017-08-01", baseURL)
	r, err := http.NewRequest(http.MethodGet, metadataEndpoint, nil)
	if err != nil {
		return nil, err
	}

	r.Header.Add("Metadata","true")

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return nil, err
	}

	metadata := new(simplifiedMetadata)
	err = json.NewDecoder(resp.Body).Decode(metadata)

	return metadata, err 
}
