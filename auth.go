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

package main

import (
	"errors"
	"io/ioutil"
	"log"

	"github.com/hashicorp/vault/api"
)

// ExternalService is an interface to represent an external
// source that should be authenticated against
type ExternalService interface {
	// Auth is used to authenticate to an external service
	Auth(*api.Client) (string, error)
}

func authenticate(client *api.Client, svc ExternalService) bool {
	var vaultToken string
	var err error

	vaultToken, err = svc.Auth(client)
	if err != nil {
		log.Println(err)
		return false
	}

	if vaultToken == "" {
		log.Printf("something weird happened, should have had the token, but do not")
		return false
	}

	err = ioutil.WriteFile(config.tokenPath, []byte(vaultToken), 0600)
	if err != nil {
		log.Printf("could not write token to %s: %v\n", config.tokenPath, err)
		return false
	}
	client.SetToken(string(vaultToken))
	return true
}

func fetchVaultToken(client *api.Client, loginData map[string]interface{}) (string, error) {
	secret, err := client.Logical().Write(config.authMount, loginData)
	if err != nil {
		return "", err
	}
	if secret == nil {
		return "", errors.New("empty response from credential provider")
	}

	return secret.Auth.ClientToken, nil
}
