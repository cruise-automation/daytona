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
	assert.Equal(t, "standard", secrets["APPLICATIONA"])
	assert.Equal(t, "nonstandard", secrets["APPLICATIONA_password"])
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
	defer os.Remove(file.Name())

	os.Setenv("VAULT_SECRET_APPLICATIONA", "secret/applicationa")
	os.Setenv("DAYTONA_SECRET_DESTINATION_APPLICATIONA", file.Name())
	defer os.Unsetenv("VAULT_SECRET_APPLICATIONA")
	defer os.Unsetenv("DAYTONA_SECRET_DESTINATION_APPLICATIONA")
	SecretFetcher(client, config)

	data, err := ioutil.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "standard", string(data))
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
	}))
	defer ts.Close()

	client, err := testhelpers.GetTestClient(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	config.SecretPayloadPath = ""
	file_lower, err := ioutil.TempFile(os.TempDir(), "secret-direct-path-arbitrary-lower-")
	if err != nil {
		t.Fatal(err)
	}
	file_upper, err := ioutil.TempFile(os.TempDir(), "secret-direct-path-arbitrary-upper-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file_lower.Name())
	defer os.Remove(file_upper.Name())

	os.Setenv("VAULT_SECRET_shut_up_and_jam", "secret/nba_jam")
	os.Setenv("DAYTONA_SECRET_DESTINATION_shut_up_and_jam", file_lower.Name())
	os.Setenv("VAULT_SECRET_shut_up_and_JAM", "secret/nba_jam_on_fire")
	os.Setenv("DAYTONA_SECRET_DESTINATION_shut_up_and_JAM", file_upper.Name())
	defer os.Unsetenv("VAULT_SECRET_shut_up_and_jam")
	defer os.Unsetenv("DAYTONA_SECRET_DESTINATION_shut_up_and_jam")
	defer os.Unsetenv("VAULT_SECRET_shut_up_and_JAM")
	defer os.Unsetenv("DAYTONA_SECRET_DESTINATION_shut_up_and_JAM")
	SecretFetcher(client, config)

	data_lower, err := ioutil.ReadFile(file_lower.Name())
	if err != nil {
		t.Fatal(err)
	}
	data_upper, err := ioutil.ReadFile(file_upper.Name())
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "from downtooooownnnnnnnn!", string(data_lower))
	assert.Equal(t, "boomshakalaka!", string(data_upper))
}

func TestSecretWalkSingleOutput(t *testing.T) {
	var config cfg.Config

	ts := httptest.NewTLSServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				list := q.Get("list")
				if list == "true" {
					fmt.Fprintln(w, `{"data": {"keys": ["credentials", "keys", "other"]}}`)
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
	defer os.Remove(file.Name())

	os.Setenv("VAULT_SECRETS_COMMON", "secret/path/common")
	defer os.Unsetenv("VAULT_SECRETS_COMMON")
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

	assert.Equal(t, "xx", secrets["keys_api_key"])
	assert.Equal(t, "aaaa", secrets["credentials_api_a"])
	assert.Equal(t, "bbbb", secrets["credentials_api_b"])
	assert.Equal(t, "password", secrets["other"])
}

func TestSecretWalkMultipleOutput(t *testing.T) {
	var config cfg.Config

	ts := httptest.NewTLSServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				list := q.Get("list")
				if list == "true" {
					fmt.Fprintln(w, `{"data": {"keys": ["credentials", "keys", "other_a", "other_A"]}}`)
				} else {
					if strings.HasSuffix(r.URL.Path, "keys") {
						fmt.Fprintln(w, `{"data": {"api_key": "xx"}}`)
					}
					if strings.HasSuffix(r.URL.Path, "credentials") {
						fmt.Fprintln(w, `{"data": {"api_a": "aaaa", "api_b":"bbbb"}}`)
					}
					if strings.HasSuffix(r.URL.Path, "other_a") {
						fmt.Fprintln(w, `{"data": {"value": "password"}}`)
					}
					if strings.HasSuffix(r.URL.Path, "other_A") {
						fmt.Fprintln(w, `{"data": {"value": "upper_case_secret_path"}}`)
					}
				}
			}))
	defer ts.Close()

	client, err := testhelpers.GetTestClient(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	file, err := ioutil.TempFile(os.TempDir(), "secret-walk-output-")
	if err != nil {
		t.Fatal(err)
	}
	dest_file, err := ioutil.TempFile(os.TempDir(), "secret-walk-dest-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())
	defer os.Remove(dest_file.Name())

	os.Setenv("VAULT_SECRETS_COMMON", "secret/path/common")
	os.Setenv("DAYTONA_SECRET_DESTINATION_other_A", dest_file.Name())
	defer os.Unsetenv("VAULT_SECRETS_COMMON")
	defer os.Unsetenv("DAYTONA_SECRET_DESTINATION_other_A")
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
	dest_data, err := ioutil.ReadFile(dest_file.Name())
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "xx", secrets["keys_api_key"])
	assert.Equal(t, "aaaa", secrets["credentials_api_a"])
	assert.Equal(t, "bbbb", secrets["credentials_api_b"])
	assert.Equal(t, "password", secrets["other_a"])
	assert.Equal(t, "upper_case_secret_path", secrets["other_A"])
	assert.Equal(t, "upper_case_secret_path", string(dest_data))
}
