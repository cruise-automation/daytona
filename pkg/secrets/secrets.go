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

package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"

	cfg "github.com/cruise-automation/daytona/pkg/config"
	"github.com/cruise-automation/daytona/pkg/helpers"
	"github.com/hashicorp/vault/api"
	"github.com/rs/zerolog/log"
)

const (
	defaultKeyName           = "value"
	secretDestinationPrefix  = "DAYTONA_SECRET_DESTINATION_"
	secretValueKeyPrefix     = "VAULT_VALUE_KEY_"
	secretStoragePathPrefix  = "VAULT_SECRET_"
	secretsStoragePathPrefix = "VAULT_SECRETS_"
)

// SecretDefinition is used for representing
// a secret definition input
type SecretDefinition struct {
	sync.RWMutex

	envkey            string
	secretID          string
	secretApex        string
	outputDestination string
	paths             []string
	secrets           map[string]string
	plural            bool
}

// SecretFetcher inspects the environment for variables that
// define secret definitions. The variables are used to guide
// the SecretFetcher in acquiring and outputting the specified secrets
func SecretFetcher(client *api.Client, config cfg.Config) {
	log.Info().Msg("Starting secret fetch")

	defs := make([]*SecretDefinition, 0)
	destinations := make(map[string]string)

	ctx := context.Background()

	parallelReader := NewParallelReader(ctx, client.Logical(), config.Workers)

	envs := os.Environ()

	// Find where all our secret keys are in vault
	for _, env := range envs {
		// VAULT_SECRET_WHATEVER=secret/application/thing
		// VAULT_SECRETS_WHATEVER=secret/application/things
		// envKey=secretPath
		pair := strings.Split(env, "=")
		envKey := pair[0]
		apex := os.Getenv(envKey)
		if apex == "" {
			continue
		}

		def := &SecretDefinition{
			envkey:     envKey,
			secretApex: apex,
			secrets:    make(map[string]string),
		}

		switch {
		case strings.HasPrefix(envKey, secretStoragePathPrefix):
			def.secretID = strings.TrimPrefix(envKey, secretStoragePathPrefix)
			def.paths = append(def.paths, apex)
		case strings.HasPrefix(envKey, secretsStoragePathPrefix):
			def.secretID = strings.TrimPrefix(envKey, secretsStoragePathPrefix)
			def.plural = true
		case strings.HasPrefix(envKey, secretDestinationPrefix):
			destinations[strings.TrimPrefix(envKey, secretDestinationPrefix)] = apex
			continue
		default:
			continue
		}

		// look for a corresponding secretDestinationPrefix key.
		// sometimes these can be cased inconsistently so we have to attempt normalization.
		// e.g.  VAULT_SECRET_APPLICATIONA --> DAYTONA_SECRET_DESTINATION_applicationa
		if dest := os.Getenv(secretDestinationPrefix + def.secretID); dest != "" {
			def.outputDestination = dest
		} else if dest := os.Getenv(secretDestinationPrefix + strings.ToLower(def.secretID)); dest != "" {
			def.outputDestination = dest
		} else if dest := os.Getenv(secretDestinationPrefix + strings.ToUpper(def.secretID)); dest != "" {
			def.outputDestination = dest
		}

		if def.plural {
			err := def.Walk(client)
			if err != nil {
				log.Fatal().Err(err).Msg("Could not iterate on the provided apex path")
			}
		}

		log.Debug().Msgf("reading paths for %s=%s", def.envkey, def.secretApex)
		err := parallelReader.ReadPaths(def)
		if err != nil {
			log.Fatal().Err(err).Msgf("failed to read paths for %s=%s", def.envkey, def.secretApex)
		}
		log.Debug().Msgf("finished reading paths for %s=%s", def.envkey, def.secretApex)

		defs = append(defs, def)
	}

	defer parallelReader.Close()
	secretPayloadPathOutput := make(map[string]string)

	// output the secret definitions
	for _, def := range defs {
		if config.SecretEnv {
			setEnvSecrets(def.secrets)
		}

		if def.outputDestination != "" {
			writeSecretsToDestination(def)
		}

		if config.SecretPayloadPath != "" {
			for k, v := range def.secrets {
				secretPayloadPathOutput[k] = v
			}
		}
	}

	if config.SecretPayloadPath != "" {
		log.Warn().Msg("secret path output functionality is planned for deprecation in version 2.0.0")
		err := writeJSONSecrets(secretPayloadPathOutput, config.SecretPayloadPath)
		if err != nil {
			log.Fatal().Err(err).Msg("Could not write JSON secrets")
		}
	}

	// attempt to locate unmatched destinations
	// VAULT_SECRETS_API_KEY = secret/yourapplication
	// it has keys like:
	// 		db_password
	// 		api_key
	// it has keys like:
	// and configured destinations such as
	// 	DAYTONA_SECRET_DESTINATION_db_password
	//	DAYTONA_SECRET_DESTINATION_api_key
	// or VAULT_SECRET_API_KEY = secret/yourapplication/api_key
	// and configured destinations such as
	//	DAYTONA_SECRET_DESTINATION_api_key
	for destKey := range destinations {
		for j := range defs {
			if defs[j].outputDestination == "" {
				secret, ok := defs[j].secrets[destKey]
				if ok {
					err := writeFile(destinations[destKey], []byte(secret))
					if err != nil {
						log.Error().Err(err).Msgf("could not write secrets to file %s", destinations[destKey])
						continue
					}
				}
			}
		}
	}
}

func writeSecretsToDestination(def *SecretDefinition) error {
	if def.plural {
		err := writeJSONSecrets(def.secrets, def.outputDestination)
		if err != nil {
			return err
		}
	} else {
		for _, secretValue := range def.secrets {
			err := writeFile(def.outputDestination, []byte(secretValue))
			if err != nil {
				return fmt.Errorf("could not write secrets to file '%s': %s", def.outputDestination, err)
			}
			log.Info().Str("outputDestination", def.outputDestination).Msg("Wrote secret")
		}
	}
	return nil
}

func writeJSONSecrets(secrets map[string]string, filepath string) error {
	payloadJSON, err := json.Marshal(secrets)
	if err != nil {
		return fmt.Errorf("failed to convert secrets payload to json: %s", err)
	}
	err = writeFile(filepath, payloadJSON)
	if err != nil {
		return fmt.Errorf("could not write secrets to file '%s': %s", filepath, err)
	}
	log.Info().Int("count", len(secrets)).Str("path", filepath).Msg("Wrote secrets")
	return nil
}

func setEnvSecrets(secrets map[string]string) error {
	for k, v := range secrets {
		err := os.Setenv(k, v)
		if err != nil {
			return fmt.Errorf("error from os.Setenv: %s", err)
		}
		log.Info().Str("var", k).Msg("Set env var")
	}
	return nil
}

func valueConverter(value interface{}) (string, error) {
	switch v := value.(type) {
	case string:
		return v, nil
	case map[string]interface{}:
		val, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return string(val), nil
	default:
		return "", fmt.Errorf("unsupported value type retrieved from vault: %T", v)
	}
}

func writeFile(path string, data []byte) error {
	err := helpers.WriteFile(path, data, 0600)
	if err != nil {
		return err
	}
	return nil
}

func (sd *SecretDefinition) addSecrets(secretResult *SecretResult) error {
	keyPath := secretResult.KeyPath
	_, keyName := path.Split(keyPath)
	secret := secretResult.Secret

	err := secretResult.Err
	if err != nil {
		return fmt.Errorf("failed to retrieve secret path %s: %w", keyPath, err)
	}
	if secret == nil {
		return fmt.Errorf("vault listed a secret, but no data was returned when reading %s - %s; very strange", keyName, keyPath)
	}
	secretData := secret.Data
	if secret.RequestID == "" && len(secretData) == 0 {
		return fmt.Errorf("vault listed a secret %s %s, but failed trying to read it; likely the rate-limiting retry attempts were exceeded", keyName, keyPath)
	}

	singleValueKey := os.Getenv(secretValueKeyPrefix + sd.secretID)
	if singleValueKey != "" && !sd.plural {
		v, ok := secretData[singleValueKey]
		if ok {
			secretValue, err := valueConverter(v)
			if err == nil {
				sd.Lock()
				sd.secrets[singleValueKey] = secretValue
				sd.Unlock()
				log.Info().Str("key", secretValueKeyPrefix+sd.secretID).Str("value", singleValueKey).Msg("Found an explicit vault value key, will only read value")
			}
			return err
		}
	}

	for k, v := range secretData {
		secretValue, err := valueConverter(v)
		if err != nil {
			return fmt.Errorf("failed to convert %v: %w", k, err)
		}
		sd.Lock()
		switch k {
		case defaultKeyName:
			sd.secrets[keyName] = secretValue
		default:
			expandedKeyName := fmt.Sprintf("%s_%s", keyName, k)
			sd.secrets[expandedKeyName] = secretValue
		}
		sd.Unlock()
	}
	return nil
}

// Walk walks a SecretDefintions SecretApex. This is used for iteration
// of the provided apex path
func (sd *SecretDefinition) Walk(client *api.Client) error {
	paths := make([]string, 0)

	list, err := client.Logical().List(sd.secretApex)
	if err != nil {
		return fmt.Errorf("there was a problem listing %s: %s", sd.secretApex, err)
	}
	if list == nil || len(list.Data) == 0 {
		return fmt.Errorf("no secrets found under: %s", sd.secretApex)
	}
	log.Info().Str("secretApex", sd.secretApex).Msg("Starting iteration")
	// list.Data is like: map[string]interface {}{"keys":[]interface {}{"API_KEY", "APPLICATION_KEY", "DB_PASS"}}
	keys, ok := list.Data["keys"].([]interface{})
	if !ok {
		return fmt.Errorf("unexpected list.Data format: %#v", list.Data)
	}
	for _, k := range keys {
		key, ok := k.(string)
		if !ok {
			return fmt.Errorf("non-string secret name: %#v", key)
		}
		if !strings.HasSuffix(key, "/") {
			paths = append(paths, path.Join(sd.secretApex, key))
		} else {
			log.Info().Str("subpath", key).Str("secretApex", sd.secretApex).Msg("found subpath while walking - only top-level path iteration is supported at this time")
		}
	}
	sd.paths = paths
	return nil
}
