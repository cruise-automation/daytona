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

package pki

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"github.com/rs/zerolog/log"
	"strings"

	cfg "github.com/cruise-automation/daytona/pkg/config"
	"github.com/hashicorp/vault/api"
)

// CertFetcher is responsible for fetching certificates & keys..
func CertFetcher(client *api.Client, config cfg.Config) {
	if config.PkiCertificate == "" || config.PkiPrivateKey == "" {
		log.Info().Msg("Certificate or private key output path is empty, will not attempt to get certificate")
		return
	}
	log.Info().Msg("Getting certificate from vault...")

	cnData := map[string]interface{}{}

	// Get certificate
	if config.PkiDomains != "" {
		domainList := strings.Split(config.PkiDomains, ",")
		if len(domainList) > 1 {
			cnData = map[string]interface{}{
				"common_name": domainList[0],
				"alt_names":   domainList[1:],
			}
		} else {
			cnData = map[string]interface{}{
				"common_name": domainList[0],
			}
		}
	}
	path := config.PkiIssuer + "/issue/" + config.PkiRole
	resp, err := client.Logical().Write(path, cnData)
	if err != nil {
		log.Panicf("Error requesting cert from Vault: %s", err)
	}
	err = writeCertData(resp, config.PkiCertificate, config.PkiPrivateKey, config.PkiUseCaChain)
	if err != nil {
		log.Panicf("Error while writing cert data: %s", err)
	}
}

func writeCertData(resp *api.Secret, certFile string, keyFile string, useCaChain bool) error {
	var certificate bytes.Buffer
	certificate.WriteString(resp.Data["certificate"].(string))
	if useCaChain && resp.Data["ca_chain"] != nil {
		chain := resp.Data["ca_chain"].([]interface{})
		for _, caCert := range chain {
			certificate.WriteString("\n")
			certificate.WriteString(caCert.(string))
		}
	}

	err := ioutil.WriteFile(certFile, []byte(certificate.String()), 0600)
	if err != nil {
		return fmt.Errorf("could not write certificate to file '%s': %s", certFile, err)
	}

	err = ioutil.WriteFile(keyFile, []byte(resp.Data["private_key"].(string)), 0600)
	if err != nil {
		return fmt.Errorf("could not write private key to file '%s': %s", keyFile, err)
	}

	return nil
}
