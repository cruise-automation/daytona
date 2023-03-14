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

	if err := checkToken(client); err == nil {
		log.Info().Msg("Found an existing, valid token via VAULT_TOKEN")
		return true
	} else {
		log.Info().Msgf("Couldn't use VAULT_TOKEN, attempting file token instead: %s", err)
	}

	if err := checkFileToken(client, config.TokenPath); err == nil {
		log.Info().Str("tokenPath", config.TokenPath).Msg("Found an existing token at token path, setting as client token")
		return true
	} else {
		log.Info().Err(err).Str("tokenPath", config.TokenPath).Msg("File token failed, trying to re-authenticate")
	}

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
func checkToken(client *api.Client) error {
	if client.Token() == "" {
		return errors.New("no pre-existing client token detected")
	}

	// Check the validity of the token. If from disk, it could be expired.
	_, err := client.Auth().Token().LookupSelf()
	if err != nil {
		client.ClearToken()
		return fmt.Errorf("existing token is invalid, clearing: %w", err)
	}

	return nil
}

// checkFileToken attempts to read a token from the specified tokenPath, and ensures it is set and valid.
// Returns false if it is unable to read the token, or the token is invalid
func checkFileToken(client *api.Client, tokenPath string) error {
	fileToken, err := ioutil.ReadFile(tokenPath)
	if err != nil {
		return fmt.Errorf("error reading existing token at %s: %w", tokenPath, err)
	}

	client.SetToken(string(fileToken))

	return checkToken(client)
}

// RenewService is responsible for renewing a vault token as it ttl approaches a threshold
func RenewService(client *api.Client, config cfg.Config) {
	interval := time.Second * time.Duration(config.RenewalInterval)
	log.Info().Dur("interval", interval).Msg("Starting the token renewer service")
	ticker := time.NewTicker(interval)

	for {
		log.Debug().Msg("attempting token renewal")
		token, err := renewToken(client, config.RenewalThreshold, config.RenewalIncrement)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to renew token")
		}

		if token != "" {
			log.Debug().Msgf("vault token renewed for %d seconds", config.RenewalIncrement)
			err = ioutil.WriteFile(config.TokenPath, []byte(token), 0600)
			if err != nil {
				log.Fatal().Str("tokenPath", config.TokenPath).Err(err).Msg("Could not write token to file. Exiting.")
			}
		} else {
			log.Debug().Msg("token was not renewed")
		}
		<-ticker.C
	}
}

// renewToken attempts to renew the client's direct token, returning a string
// copy of the token, if it was renewed. Otherwise, the existing client token
// should be considered valid.
func renewToken(client *api.Client, threshold, increment int64) (string, error) {
	result, err := client.Auth().Token().LookupSelf()
	if err != nil {
		return "", fmt.Errorf("failed to looking existing client token: %w", err)
	}

	ttl, err := result.TokenTTL()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve the client token ttl: %w", err)
	}

	ttlSeconds := ttl.Seconds()
	if ttlSeconds == 0 {
		return "", errors.New("cannot renew an expired token")
	}

	if ttlSeconds < float64(threshold) {
		secret, err := client.Auth().Token().RenewSelf(int(increment))
		if err != nil {
			return "", fmt.Errorf("failed to renew the existing token: %w", err)
		}

		if secret == nil {
			return "", errors.New("renewal payload was empty")
		}

		if secret.Auth == nil {
			return "", errors.New("renewal auth payload was empty")
		}

		if secret.Auth.ClientToken == "" {
			return "", errors.New("client token was empty, this was unexpected ")
		}
		return secret.Auth.ClientToken, nil
	}
	return "", nil
}
