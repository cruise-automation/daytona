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
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/cenkalti/backoff"
	cfg "github.com/cruise-automation/daytona/pkg/config"
	"github.com/hashicorp/vault/api"
	"github.com/rs/zerolog/log"
)

// Authenticator is an interface to represent an external
// source that should be authenticated against.
type Authenticator interface {
	// Auth is used to authenticate to an external service
	Auth(*api.Client, cfg.Config) (string, error)
}

// authenticate authenticates with Vault, returns true if successful
func authenticate(client *api.Client, config cfg.Config, svc Authenticator) bool {
	var vaultToken string
	var err error

	vaultToken, err = svc.Auth(client, config)
	if err != nil {
		log.Error().Err(err).Msg("failed to retrieve vault token")
		return false
	}

	if vaultToken == "" {
		log.Error().Msg("something weird happened, should have had the token, but do not")
		return false
	}

	err = ioutil.WriteFile(config.TokenPath, []byte(vaultToken), 0600)
	if err != nil {
		log.Error().Err(err).Str("tokenPath", config.TokenPath).Msg("could not write token")
		return false
	}

	client.SetToken(vaultToken)
	return true
}

func fetchVaultToken(client *api.Client, config cfg.Config, loginData map[string]interface{}) (string, error) {
	secret, err := client.Logical().Write(config.AuthMount, loginData)
	if err != nil {
		return "", err
	}
	if secret == nil {
		return "", errors.New("empty response from credential provider")
	}

	return secret.Auth.ClientToken, nil
}

// EnsureAuthenticated verifies we have a valid token, or attempts to fetch a new one.
// Returns false if it is unable to become authenticated.
func EnsureAuthenticated(client *api.Client, config cfg.Config) bool {
	// Vault Go API will read a token from VAULT_TOKEN if it exists.
	// If it didn't find one, attempt to read token from disk.
	log.Info().Msg("Checking for an existing, valid vault token")

	if checkToken(client) {
		return true
	}

	log.Info().Msg("No token found in VAULT_TOKEN env, checking path")

	if checkFileToken(client, config.TokenPath) {
		return true
	}

	log.Info().Str("tokenPath", config.TokenPath).Msg("No token found, trying to re-authenticate")

	bo := backoff.NewExponentialBackOff()
	bo.MaxInterval = time.Second * 15

	if config.InfiniteAuth {
		log.Info().Msg("Infinite authentication enabled.")
		bo.MaxElapsedTime = 0
	} else {
		log.Info().Int64("maxRetry", config.MaximumAuthRetry).Msg("Authentication will be attempted until max retry reached")
		bo.MaxElapsedTime = time.Second * time.Duration(config.MaximumAuthRetry)
	}

	var svc Authenticator
	switch {
	case config.K8SAuth:
		svc = &K8SService{}
	case config.AWSAuth:
		svc = &AWSService{}
	case config.GCPAuth:
		svc = &GCPService{}
	case config.AzureAuth:
		svc = &AzureService{}
	default:
		panic("should never get here")
	}

	authTicker := backoff.NewTicker(bo)
	for range authTicker.C {
		log.Info().Msg("Attempting to authenticate.")

		if authenticate(client, config, svc) {
			log.Info().Msg("Authentication succeeded.")
			return true
		}
	}

	return false
}

// checkToken ensures the currently set token token is valid, or unsets it.
// Returns true if the token is valid
func checkToken(client *api.Client) bool {
	if client.Token() == "" {
		return false
	}

	// Check the validity of the token. If from disk, it could be expired.
	_, err := client.Auth().Token().LookupSelf()
	if err != nil {
		log.Warn().Err(err).Msg("Invalid token. Deleting invalid token.")
		client.ClearToken()

		return false
	}

	return true
}

// checkFileToken attempts to read a token from the specified tokenPath, and ensures it is set and valid.
// Returns false if it is unable to read the token, or the token is invalid
func checkFileToken(client *api.Client, tokenPath string) bool {
	fileToken, err := ioutil.ReadFile(tokenPath)
	if err != nil {
		log.Info().Str("tokenPath", tokenPath).Msg("Error reading existing token")
		return false
	}

	log.Info().Str("tokenPath", tokenPath).Msg("Found an existing token, setting as client token")
	client.SetToken(string(fileToken))

	return checkToken(client)
}

// RenewService is responsible for renewing a vault token as it ttl approaches a threshold
func RenewService(client *api.Client, config cfg.Config) {
	interval := time.Second * time.Duration(config.RenewalInterval)
	log.Info().Dur("interval", interval).Msg("Starting the token renewer service")
	ticker := time.Tick(interval)

	for {
		result, err := client.Auth().Token().LookupSelf()
		if err != nil {
			log.Fatal().Err(err).Msg("The existing token failed renewal. Exiting.")
		}

		ttl, err := result.TokenTTL()
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to parse the token's TTL from JSON. Exiting.")
		}

		if ttl.Seconds() < float64(config.RenewalThreshold) {
			fmt.Println("token ttl of", ttl.Seconds(), "is below threshold of", config.RenewalThreshold, ", renewing to", config.RenewalIncrement)
			secret, err := client.Auth().Token().RenewSelf(int(config.RenewalIncrement))
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to renew the existing token. Exiting.")
			}

			client.SetToken(secret.Auth.ClientToken)

			err = ioutil.WriteFile(config.TokenPath, []byte(secret.Auth.ClientToken), 0600)
			if err != nil {
				log.Fatal().Str("tokenPath", config.TokenPath).Err(err).Msg("Could not write token to file. Exiting.")
			}
		} else {
			log.Info().Dur("tokenTTL", ttl).Int64("renewalThreshold", config.RenewalThreshold).Msg("Existing token ttl is still above the threshold, skipping renewal")
		}
		<-ticker
	}
}
