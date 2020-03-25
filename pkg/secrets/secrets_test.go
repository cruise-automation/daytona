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
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	cfg "github.com/cruise-automation/daytona/pkg/config"
	"github.com/cruise-automation/daytona/pkg/helpers/testhelpers"

	"github.com/stretchr/testify/assert"
)

func TestSecretPath(t *testing.T) {
	var config cfg.Config

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `
		{
			"auth": null,
			"data": {
			  "value": "standard",
			  "password": "nonstandard"
			},
			"lease_duration": 3600,
			"lease_id": "",
			"renewable": false
		  }
		`)
	}))
	defer ts.Close()
	client, err := testhelpers.GetTestClient(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	file, err := ioutil.TempFile(os.TempDir(), "secret-path-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())

	os.Setenv("VAULT_SECRET_APPLICATIONA", "secret/applicationA")
	defer os.Unsetenv("VAULT_SECRET_APPLICATIONA")
	config.SecretPayloadPath = file.Name()
	config.Workers = 3
	SecretFetcher(client, config)

	secrets := make(map[string]string)
	data, err := ioutil.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal(data, &secrets)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "standard", secrets["applicationA"])
	assert.Equal(t, "nonstandard", secrets["applicationA_password"])
}

func TestSecretDirectPath(t *testing.T) {
	var config cfg.Config

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `
		{
			"auth": null,
			"data": {
			  "value": "standard"
			},
			"lease_duration": 3600,
			"lease_id": "",
			"renewable": false
		  }
		`)
	}))
	defer ts.Close()

	client, err := testhelpers.GetTestClient(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	config.SecretPayloadPath = ""
	file, err := ioutil.TempFile(os.TempDir(), "secret-direct-path-")
	if err != nil {
		t.Fatal(err)
	}

	arbFile, err := ioutil.TempFile(os.TempDir(), "secret-direct-path-arb-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())
	defer os.Remove(arbFile.Name())

	os.Setenv("VAULT_SECRET_APPLICATIONA", "secret/applicationa")
	os.Setenv("DAYTONA_SECRET_DESTINATION_applicationa", file.Name())
	os.Setenv("VAULT_SECRET_HELLO", "secret/applicationa")
	os.Setenv("DAYTONA_SECRET_DESTINATION_HELLO", arbFile.Name())

	defer os.Unsetenv("VAULT_SECRET_APPLICATIONA")
	defer os.Unsetenv("DAYTONA_SECRET_DESTINATION_applicationa")
	defer os.Unsetenv("VAULT_SECRET_HELLO")
	defer os.Unsetenv("DAYTONA_SECRET_DESTINATION_HELLO")
	SecretFetcher(client, config)

	data, err := ioutil.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	arbData, err := ioutil.ReadFile(arbFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "standard", string(data))
	assert.Equal(t, "standard", string(arbData))
}

func TestSecretDirectPathArbitraryIdentifiers(t *testing.T) {
	var config cfg.Config

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "nba_jam") {
			fmt.Fprintln(w, `
			{
				"auth": null,
				"data": {
				  "value": "from downtooooownnnnnnnn!"
				},
				"lease_duration": 3600,
				"lease_id": "",
				"renewable": false
			  }
			`)
		}
		if strings.HasSuffix(r.URL.Path, "nba_jam_on_fire") {
			fmt.Fprintln(w, `
			{
				"auth": null,
				"data": {
				  "value": "boomshakalaka!"
				},
				"lease_duration": 3600,
				"lease_id": "",
				"renewable": false
			  }
			`)
		}
		if strings.HasSuffix(r.URL.Path, "space_jam") {
			fmt.Fprintln(w, `
			{
				"auth": null,
				"data": {
				  "value": "Here's your chance, do your dance at the Space Jam!"
				},
				"lease_duration": 3600,
				"lease_id": "",
				"renewable": false
			  }
			`)
		}
	}))
	defer ts.Close()

	client, err := testhelpers.GetTestClient(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	config.SecretPayloadPath = ""
	fileLower, err := ioutil.TempFile(os.TempDir(), "secret-direct-path-arbitrary-lower-")
	if err != nil {
		t.Fatal(err)
	}
	fileUpper, err := ioutil.TempFile(os.TempDir(), "secret-direct-path-arbitrary-upper-")
	if err != nil {
		t.Fatal(err)
	}

	fileInconsistent, err := ioutil.TempFile(os.TempDir(), "secret-direct-path-arbitrary-inconsistent-")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(fileLower.Name())
	defer os.Remove(fileUpper.Name())
	defer os.Remove(fileInconsistent.Name())

	os.Setenv("VAULT_SECRET_shut_up_and_jam", "secret/nba_jam")
	os.Setenv("DAYTONA_SECRET_DESTINATION_shut_up_and_jam", fileLower.Name())
	os.Setenv("VAULT_SECRET_shut_up_and_JAM", "secret/nba_jam_on_fire")
	os.Setenv("DAYTONA_SECRET_DESTINATION_shut_up_and_JAM", fileUpper.Name())
	os.Setenv("VAULT_SECRET_WHOISMIKEJONES", "secret/space_jam")
	os.Setenv("DAYTONA_SECRET_DESTINATION_whoismikejones", fileInconsistent.Name())
	defer os.Unsetenv("VAULT_SECRET_shut_up_and_jam")
	defer os.Unsetenv("DAYTONA_SECRET_DESTINATION_shut_up_and_jam")
	defer os.Unsetenv("VAULT_SECRET_shut_up_and_JAM")
	defer os.Unsetenv("DAYTONA_SECRET_DESTINATION_shut_up_and_JAM")
	defer os.Unsetenv("VAULT_SECRET_WHOISMIKEJONES")
	defer os.Unsetenv("DAYTONA_SECRET_DESTINATION_whoismikejones")
	SecretFetcher(client, config)

	dataLower, err := ioutil.ReadFile(fileLower.Name())
	if err != nil {
		t.Fatal(err)
	}
	dataUpper, err := ioutil.ReadFile(fileUpper.Name())
	if err != nil {
		t.Fatal(err)
	}
	dataInconsistent, err := ioutil.ReadFile(fileInconsistent.Name())
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "from downtooooownnnnnnnn!", string(dataLower))
	assert.Equal(t, "boomshakalaka!", string(dataUpper))
	assert.Equal(t, "Here's your chance, do your dance at the Space Jam!", string(dataInconsistent))
}

func TestSecretAWalk(t *testing.T) {
	var config cfg.Config

	ts := httptest.NewTLSServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				list := q.Get("list")
				if list == "true" {
					fmt.Fprintln(w, `{"data": {"keys": ["credentials", "keys", "other", "subpath/"]}}`)
				} else {
					if strings.HasSuffix(r.URL.Path, "keys") {
						fmt.Fprintln(w, `{"data": {"api_key": "xx"}}`)
					}
					if strings.HasSuffix(r.URL.Path, "credentials") {
						fmt.Fprintln(w, `{"data": {"api_a": "aaaa", "api_b":"bbbb"}}`)
					}
					if strings.HasSuffix(r.URL.Path, "other") {
						fmt.Fprintln(w, `{"data": {"value": "password"}}`)
					}
					if strings.HasSuffix(r.URL.Path, "subpath/") {
						w.WriteHeader(404)
						fmt.Fprintln(w, `{"errors": []}`)
					}
				}
			}))
	defer ts.Close()

	client, err := testhelpers.GetTestClient(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	file, err := ioutil.TempFile(os.TempDir(), "secret-walk-")
	if err != nil {
		t.Fatal(err)
	}

	destinationPrefixFile, err := ioutil.TempFile(os.TempDir(), "secret-walk-destination-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())
	defer os.Remove(destinationPrefixFile.Name())

	os.Setenv("VAULT_SECRETS_COMMON", "secret/path/common")
	os.Setenv("DAYTONA_SECRET_DESTINATION_COMMON", destinationPrefixFile.Name())
	defer os.Unsetenv("VAULT_SECRETS_COMMON")
	defer os.Unsetenv("VAULT_SECRETS_GENERIC")

	config.SecretPayloadPath = file.Name()
	SecretFetcher(client, config)

	secrets := make(map[string]string)
	data, err := ioutil.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal(data, &secrets)
	if err != nil {
		t.Fatal(err)
	}

	destSecrets := make(map[string]string)
	destinationData, err := ioutil.ReadFile(destinationPrefixFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal(destinationData, &destSecrets)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "xx", secrets["keys_api_key"])
	assert.Equal(t, "aaaa", secrets["credentials_api_a"])
	assert.Equal(t, "bbbb", secrets["credentials_api_b"])
	assert.Equal(t, "password", secrets["other"])

	assert.Equal(t, "xx", destSecrets["keys_api_key"])
	assert.Equal(t, "aaaa", destSecrets["credentials_api_a"])
	assert.Equal(t, "bbbb", destSecrets["credentials_api_b"])
	assert.Equal(t, "password", destSecrets["other"])
}
