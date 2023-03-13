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
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	cfg "github.com/cruise-automation/daytona/pkg/config"
	"github.com/cruise-automation/daytona/pkg/helpers/testhelpers"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// nolint: gosec
const (
	testToken              = "s.iyNUhq8Ov4hIAx6snw5mB2nL"
	testTokenLookupPayload = `
{
  "data": {
	"accessor": "8609694a-cdbc-db9b-d345-e782dbb562ed",
	"creation_time": 1523979354,
	"creation_ttl": 2764800,
	"display_name": "ldap2-hortensia",
	"entity_id": "7d2e3179-f69b-450c-7179-ac8ee8bd8ca9",
	"expire_time": "2018-05-19T11:35:54.466476215-04:00",
	"explicit_max_ttl": 0,
	"id": "cf64a70f-3a12-3f6c-791d-6cef6d390eed",
	"identity_policies": [
	  "dev-group-policy"
	],
	"issue_time": "2018-04-17T11:35:54.466476078-04:00",
	"meta": {
	  "username": "hortensia"
	},
	"num_uses": 0,
	"orphan": true,
	"path": "auth/ldap2/login/hortensia",
	"policies": [
	  "default",
	  "testgroup2-policy"
	],
	"renewable": true,
	"ttl": 2764790
  }
}
`
	testAuthResponse = `
{
	"auth": {
	  "client_token": "b.AAAAAQL_tyer_gNuQqvQYPVQgsNxjap_YW1NB2m4CDHHadQo7rF2XLFGdw-NJplAZNKbfloOvifrbpRCGdgG1taTqmC7D-a_qftN64zeL10SmNwEoDTiPzC_1aS1KExbtVftU3Sx16cBVqaynwsYRDfVnfTAffE",
	  "accessor": "0e9e354a-520f-df04-6867-ee81cae3d42d",
	  "policies": [
		"default",
		"dev",
		"prod"
	  ],
	  "metadata": {
		"project_id": "my-project",
		"role": "my-role",
		"service_account_email": "dev1@project-123456.iam.gserviceaccount.com",
		"service_account_id": "111111111111111111111"
	  },
	  "lease_duration": 2764800,
	  "renewable": true
	}
  }
`
)

func TestAuthPanic(t *testing.T) {
	var config cfg.Config
	client, err := testhelpers.GetTestClient("nan")
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken(testToken)
	config.MaximumAuthRetry = 1
	assert.Panics(t, func() { EnsureAuthenticated(client, config) }, "The code did not panic when it should have")
}

type MockedService struct {
	mock.Mock
}

func (m *MockedService) Auth(c *api.Client, config cfg.Config) (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func TestServiceAuth(t *testing.T) {
	var config cfg.Config
	client, err := testhelpers.GetTestClient("none")
	if err != nil {
		t.Fatal(err)
	}

	testService := new(MockedService)
	testService.On("Auth").Return("62b858f9-529c-6b26-e0b8-0457b6aacdb4", nil)

	tokenFile, err := ioutil.TempFile(os.TempDir(), "vault-token-test")
	if err != nil {
		t.Fatal(err)
	}
	config.TokenPath = tokenFile.Name()
	defer os.Remove(tokenFile.Name())

	assert.Equal(t, true, authenticate(client, config, testService))
	assert.Equal(t, "62b858f9-529c-6b26-e0b8-0457b6aacdb4", client.Token())
}

func TestFetchVaultToken(t *testing.T) {
	var config cfg.Config
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, testAuthResponse)
	}))
	defer ts.Close()

	client, err := testhelpers.GetTestClient(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	loginData := map[string]interface{}{
		"this": "that",
	}
	token, err := fetchVaultToken(client, config, loginData)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "b.AAAAAQL_tyer_gNuQqvQYPVQgsNxjap_YW1NB2m4CDHHadQo7rF2XLFGdw-NJplAZNKbfloOvifrbpRCGdgG1taTqmC7D-a_qftN64zeL10SmNwEoDTiPzC_1aS1KExbtVftU3Sx16cBVqaynwsYRDfVnfTAffE", token)
}

func TestFetchVaultTokenFailure(t *testing.T) {
	var config cfg.Config
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprintln(w, `{"errors":["big bad error"]}`)
	}))
	defer ts.Close()

	client, err := testhelpers.GetTestClient(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	loginData := map[string]interface{}{
		"this": "that",
	}
	_, err = fetchVaultToken(client, config, loginData)
	if err == nil {
		t.Fatal("no error was returned when one was expected")
	}
	assert.Contains(t, err.Error(), "big bad error")
}

var tokenLookupResponse = `{
	"auth": {
	  "client_token": "ABCD",
	  "policies": ["web", "stage"],
	  "metadata": {
		"user": "robert"
	  },
	  "lease_duration": 10,
	  "renewable": true
	}
}`

var tokenRenewalResponse = `{
	"auth": {
	  "client_token": "brand-new-token",
	  "policies": ["web", "stage"],
	  "metadata": {
		"user": "robert"
	  },
	  "lease_duration": 12,
	  "renewable": true
	}
}`

func TestRenewal(t *testing.T) {
	t.Run("dont_renew_expired", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"auth":{"lease_duration": 0}}`)
		}))

		t.Cleanup(ts.Close)
		client, err := testhelpers.GetTestClient(ts.URL)
		if err != nil {
			t.Fatal(err)
		}
		expected := "cannot renew an expired token"
		_, err = renewToken(client, 60, 60)
		if err.Error() != expected {
			t.Fatalf("expected %s, got %s", expected, err.Error())
		}
	})

	t.Run("nil_payload", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/auth/token/lookup-self":
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, tokenLookupResponse)
			default:
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, `{}`)
			}
		}))

		t.Cleanup(ts.Close)
		client, err := testhelpers.GetTestClient(ts.URL)
		if err != nil {
			t.Fatal(err)
		}
		expected := "renewal auth payload was empty"
		_, err = renewToken(client, 60, 60)
		if err.Error() != expected {
			t.Fatalf("expected %s, got %s", expected, err.Error())
		}
	})

	t.Run("no_renewal", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/auth/token/lookup-self":
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, tokenLookupResponse)
			default:
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, tokenRenewalResponse)
			}
		}))

		t.Cleanup(ts.Close)
		client, err := testhelpers.GetTestClient(ts.URL)
		if err != nil {
			t.Fatal(err)
		}
		token, err := renewToken(client, 5, 60)
		if err != nil {
			t.Fatal(err)
		}

		if token != "" {
			t.Fatalf("didn't expect a new token, but received %s", token)

		}
	})

	t.Run("basic_renewal", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/auth/token/lookup-self":
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, tokenLookupResponse)
			default:
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, tokenRenewalResponse)
			}
		}))

		t.Cleanup(ts.Close)
		client, err := testhelpers.GetTestClient(ts.URL)
		if err != nil {
			t.Fatal(err)
		}
		token, err := renewToken(client, 60, 60)
		if err != nil {
			t.Fatal(err)
		}

		if token != "brand-new-token" {
			t.Fatalf("expected to receive a token with %s, got %s", "brand-new-token", token)

		}
	})
}
