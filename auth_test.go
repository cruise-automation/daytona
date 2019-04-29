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
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAuthPanic(t *testing.T) {
	client, err := getTestClient("nan")
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken(testToken)
	config.maximumAuthRetry = 1
	assert.Panics(t, func() { ensureAuthenticated(client) }, "The code did not panic when it should have")
}

type MockedService struct {
	mock.Mock
}

func (m *MockedService) Auth(c *api.Client) (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func TestServiceAuth(t *testing.T) {
	client, err := getTestClient("none")
	if err != nil {
		t.Fatal(err)
	}

	testService := new(MockedService)
	testService.On("Auth").Return("62b858f9-529c-6b26-e0b8-0457b6aacdb4", nil)

	tokenFile, err := ioutil.TempFile(os.TempDir(), "vault-token-test")
	if err != nil {
		t.Fatal(err)
	}
	config.tokenPath = tokenFile.Name()
	defer os.Remove(tokenFile.Name())

	assert.Equal(t, true, authenticate(client, testService))
	assert.Equal(t, "62b858f9-529c-6b26-e0b8-0457b6aacdb4", client.Token())
}

func TestFetchVaultToken(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, testAuthResponse)
	}))
	defer ts.Close()

	client, err := getTestClient(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	loginData := map[string]interface{}{
		"this": "that",
	}
	token, err := fetchVaultToken(client, loginData)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "b.AAAAAQL_tyer_gNuQqvQYPVQgsNxjap_YW1NB2m4CDHHadQo7rF2XLFGdw-NJplAZNKbfloOvifrbpRCGdgG1taTqmC7D-a_qftN64zeL10SmNwEoDTiPzC_1aS1KExbtVftU3Sx16cBVqaynwsYRDfVnfTAffE", token)
}

func TestFetchVaultTokenFailure(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprintln(w, `{"errors":["big bad error"]}`)
	}))
	defer ts.Close()

	client, err := getTestClient(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	loginData := map[string]interface{}{
		"this": "that",
	}
	_, err = fetchVaultToken(client, loginData)
	if err == nil {
		t.Fatal("no error was returned when one was expected")
	}
	assert.Contains(t, err.Error(), "big bad error")
}
