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

package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"

	cfg "github.com/cruise-automation/daytona/pkg/config"
	"github.com/hashicorp/vault/api"
)

const defaultKeyName = "value"
const secretLocationPrefix = "DAYTONA_SECRET_DESTINATION_"

// SecretFetcher is responsible for fetching sercrets..
func SecretFetcher(client *api.Client, config cfg.Config) {
	locations := prefixSecretLocationDefined()
	if config.SecretPayloadPath == "" && !config.SecretEnv && len(locations) == 0 {
		log.Println("No secret output method was configured, will not attempt to retrieve secrets")
		return
	}

	log.Println("Starting secret fetch")
	secrets := make(map[string]string)

	envs := os.Environ()
	// Find where all our secret keys are in vault
	for _, v := range envs {
		pair := strings.Split(v, "=")
		envKey := pair[0]
		secretPath := os.Getenv(envKey)
		if secretPath == "" {
			continue
		}

		// Single secret
		if strings.HasPrefix(envKey, "VAULT_SECRET_") {
			err := addSecrets(client, secrets, secretPath)
			if err != nil {
				log.Fatalln(err)
			}
		}
		// Path containing multiple secrets
		if strings.HasPrefix(envKey, "VAULT_SECRETS_") {
			paths, err := listSecrets(client, secretPath)
			if err != nil {
				log.Fatalln(err)
			}
			for _, path := range paths {
				err := addSecrets(client, secrets, path)
				if err != nil {
					log.Fatalln(err)
				}
			}
		}
	}

	// Write all secrets to a configured json file
	if config.SecretPayloadPath != "" {
		err := writeJSONSecrets(secrets, config.SecretPayloadPath)
		if err != nil {
			log.Fatalln(err)
		}
	}

	// Write all secrets to their specified locations
	if len(locations) != 0 {
		err := writeSecretsToDestination(secrets, locations)
		if err != nil {
			log.Fatalln(err)
		}
	}

	// Export secret environment variables if configured, and we are acting as a stub entrypoint for a container
	if config.SecretEnv {
		err := setEnvSecrets(secrets)
		if err != nil {
			log.Fatalln(err)
		}
	}
}

// listSecrets returns a list of absolute paths to all secrets located under "secretPath",
// or an error
func listSecrets(client *api.Client, secretPath string) ([]string, error) {
	paths := make([]string, 0, 10)

	list, err := client.Logical().List(secretPath)
	if err != nil {
		return nil, fmt.Errorf("there was a problem listing %s: %s", secretPath, err)
	}
	if list == nil || len(list.Data) == 0 {
		return nil, fmt.Errorf("no secrets found under: %s", secretPath)
	}
	log.Println("Starting iteration on", secretPath)
	// list.Data is like: map[string]interface {}{"keys":[]interface {}{"API_KEY", "APPLICATION_KEY", "DB_PASS"}}
	keys, ok := list.Data["keys"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected list.Data format: %#v", list.Data)
	}
	for _, k := range keys {
		key, ok := k.(string)
		if !ok {
			return nil, fmt.Errorf("non-string secret name: %#v", key)
		}
		paths = append(paths, path.Join(secretPath, key))
	}

	return paths, nil
}

func writeSecretsToDestination(secrets map[string]string, locations map[string]string) error {
	for secret, secretValue := range secrets {
		secretDestination, ok := locations[secret]
		if !ok {
			continue
		}
		err := ioutil.WriteFile(secretDestination, []byte(secretValue), 0600)
		if err != nil {
			return fmt.Errorf("could not write secrets to file '%s': %s", secretDestination, err)
		}
		log.Printf("Wrote secret to %s\n", secretDestination)
	}
	return nil
}

func writeJSONSecrets(secrets map[string]string, filepath string) error {
	payloadJSON, err := json.Marshal(secrets)
	if err != nil {
		return fmt.Errorf("failed to convert secrets payload to json: %s", err)
	}
	err = ioutil.WriteFile(filepath, payloadJSON, 0600)
	if err != nil {
		return fmt.Errorf("could not write secrets to file '%s': %s", filepath, err)
	}
	log.Printf("Wrote %d secrets to %s\n", len(secrets), filepath)
	return nil
}

func setEnvSecrets(secrets map[string]string) error {
	for k, v := range secrets {
		err := os.Setenv(k, v)
		if err != nil {
			return fmt.Errorf("Error from os.Setenv: %s", err)
		}
		log.Printf("Set env var: %s\n", k)
	}
	return nil
}

func addSecret(secrets map[string]string, k string, v interface{}) error {
	if secrets[k] != "" {
		return errors.New("duplicate secret name: " + k)
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Errorf("secret '%s' has non-string value: %#v", k, v)
	}
	secrets[k] = s
	return nil
}

func addSecrets(client *api.Client, secrets map[string]string, keyPath string) error {
	_, keyName := path.Split(keyPath)

	secret, err := client.Logical().Read(keyPath)
	if err != nil {
		log.Fatalf("Failed retrieving secret %s: %s\n", keyPath, err)
	}
	if secret == nil {
		log.Fatalf("Vault listed a secret '%s', but got not-found trying to read it at '%s'; very strange\n", keyName, keyPath)
	}
	secretData := secret.Data

	// Return last error encountered during processing, if any
	var lastErr error

	// detect and fetch defaultKeyName
	if secretData[defaultKeyName] != nil {
		err := addSecret(secrets, keyName, secretData[defaultKeyName])
		if err != nil {
			lastErr = err
		}
		delete(secretData, defaultKeyName)
	}

	// iterate over remaining map entries
	for k, v := range secretData {
		expandedKeyName := fmt.Sprintf("%s_%s", keyName, k)
		err := addSecret(secrets, expandedKeyName, v)
		if err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// prefixSecretLocationDefined checks whether any of the configured
// secrets for fetching are using an explicit destination.
func prefixSecretLocationDefined() map[string]string {
	locations := make(map[string]string)
	envs := os.Environ()
	for _, v := range envs {
		pair := strings.Split(v, "=")
		envKey := pair[0]
		if strings.HasPrefix(envKey, secretLocationPrefix) {
			secret := strings.TrimPrefix(envKey, secretLocationPrefix)
			locations[secret] = os.Getenv(envKey)
		}
	}
	return locations
}
