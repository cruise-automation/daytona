package daytona

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cruise-automation/daytona/pkg/helpers/testhelpers"

	"github.com/stretchr/testify/assert"
)

type ConfigWithSecrets struct {
	Nothign    string
	Password   string            `vault_path:"secret/application/password" vault_key:"password"`
	DBPassword string            `vault_path_key:"password"`
	AnInteger  int64             `vault_path_key:"password" vault_key:"an_int"`
	AFloat     float64           `vault_path_key:"password" vault_key:"a_float"`
	ABool      bool              `vault_path_key:"password" vault_key:"a_bool"`
	ADuration  time.Duration     `vault_path_key:"password" vault_key:"a_duration"`
	AMap       map[string]string `vault_path_key:"password" vault_key:"a_map"`
	Slice      []string          `vault_path_key:"password" vault_key:"a_slice"`
	AMismatch  float64           `vault_path_key:"password" vault_key:"a_mismatch"`
	Embedded
}

type Embedded struct {
	PrivateKey string `vault_path_key:"password" vault_key:"private_key"`
}

func TestUnmarshalSecret(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/secret/application/password":
			fmt.Fprintln(w, `
			{
				"auth": null,
				"data": {
				  "value": "standard",
				  "password": "nonstandard",
				  "private_key": "BEGIN PRIVATE KEY",
				  "an_int": 12,
				  "a_float": 6.66,
				  "a_bool": true,
				  "a_duration": "7h",
				  "a_mismatch": "7xL"
				},
				"lease_duration": 3600,
				"lease_id": "",
				"renewable": false
			  }
			`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()
	client, err := testhelpers.GetTestClient(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	cfg := ConfigWithSecrets{}

	err = UnmarshalSecrets(client, &cfg, "secret/application")
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "standard", cfg.DBPassword)
	assert.Equal(t, "nonstandard", cfg.Password)
	assert.Equal(t, "BEGIN PRIVATE KEY", cfg.Embedded.PrivateKey)
	assert.Equal(t, time.Hour*7, cfg.ADuration)
	assert.Equal(t, 6.66, cfg.AFloat)
	assert.Equal(t, int64(12), cfg.AnInteger)
	assert.Equal(t, true, cfg.ABool)
}
