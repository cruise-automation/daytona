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
package auth

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"

	cfg "github.com/cruise-automation/daytona/pkg/config"
	"github.com/hashicorp/vault/api"
)

// K8SService is an external service that vault can authenticate requests against
type K8SService struct{}

// Auth is used to authenticate to an external service
func (k *K8SService) Auth(client *api.Client, config cfg.Config) (string, error) {
	log.Println("Attempting kubernetes auth..")
	if config.K8STokenPath == "" {
		return "", fmt.Errorf("kubernetes auth token path is mssing")
	}

	data, err := ioutil.ReadFile(config.K8STokenPath)
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
