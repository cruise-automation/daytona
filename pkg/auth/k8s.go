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
	"bytes"
	"errors"
	"fmt"
	"os"

	"cloud.google.com/go/compute/metadata"
	"github.com/briankassouf/jose/jws"
	cfg "github.com/cruise-automation/daytona/pkg/config"
	"github.com/hashicorp/vault/api"
	"github.com/rs/zerolog/log"
)

var (
	// ErrInferRoleClaims is returns when the authenticator fails to infer a role name
	ErrInferRoleClaims = errors.New("could not parse service-account name / role name from claims")
)

// K8SService is an external service that vault can authenticate requests against
type K8SService struct{}

// Auth is used to authenticate to an external service
func (k *K8SService) Auth(client *api.Client, config cfg.Config) (string, error) {
	log.Info().Msg("Attempting kubernetes auth..")
	if config.K8STokenPath == "" {
		return "", fmt.Errorf("kubernetes auth token path is mssing")
	}

	data, err := os.ReadFile(config.K8STokenPath)
	if err != nil {
		return "", fmt.Errorf("could not read JWT from file %s", err.Error())
	}
	jwt := string(bytes.TrimSpace(data))
	loginData := map[string]interface{}{
		"role": config.VaultAuthRoleName,
		"jwt":  jwt,
	}
	return fetchVaultToken(client, config, loginData)
}

// InferK8SConfig attempts to replace default configuration parameters on K8S with ones inferred from the k8s environment
func InferK8SConfig(config *cfg.Config) {
	log.Info().Msg("Attempting to automatically infer some k8s configuration data")
	if config.VaultAuthRoleName == "" {
		saName, err := inferVaultAuthRoleName(config)
		if err != nil {
			log.Warn().Err(err).Msg("Unable to infer SA Name")
		} else {
			config.VaultAuthRoleName = saName
		}
	}

	// Check for default value
	if config.K8SAuthMount == "kubernetes" {
		vaultAuthMount, err := inferVaultAuthMount()
		if err != nil {
			log.Warn().Err(err).Msg("Unable to infer K8S Vault Auth Mount")
		} else {
			config.K8SAuthMount = vaultAuthMount
		}
	}
}

// inferVaultAuthRoleName figures out the current k8s service account name, and returns it.
// This can be assumed to match a a vault role if configured properly.
func inferVaultAuthRoleName(config *cfg.Config) (string, error) {
	data, err := os.ReadFile(config.K8STokenPath)
	if err != nil {
		return "", fmt.Errorf("could not read JWT from file %s", err.Error())
	}

	jwt := bytes.TrimSpace(data)

	// Parse into JWT
	parsedJWT, err := jws.ParseJWT(jwt)
	if err != nil {
		return "", err
	}

	var roleName string

	if name, ok := parsedJWT.Claims().Get("kubernetes.io/serviceaccount/service-account.name").(string); !ok {
		if domain, ok := parsedJWT.Claims().Get("kubernetes.io").(map[string]interface{}); ok {
			if sa, ok := domain["serviceaccount"].(map[string]interface{}); ok {
				if name, ok := sa["name"].(string); ok {
					roleName = name
				}
			}
		}
	} else {
		roleName = name
	}
	if roleName == "" {
		return "", ErrInferRoleClaims
	}

	return roleName, nil
}

// inferVaultAuthMount attempts to figure out where the auth path for the current k8s cluster is in vault, and return it
func inferVaultAuthMount() (string, error) {
	clusterName, err := metadata.InstanceAttributeValue("cluster-name")

	return fmt.Sprintf("kubernetes-gcp-%s", clusterName), err
}
