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
				  "a_bad_string": 9,
				  "an_int": 12,
				  "a_string_int": "12",
				  "a_bad_int": "xxx",
				  "a_float": 6.66,
				  "a_string_float": "6.66",
				  "a_bad_float": "xxx",
				  "a_bool": true,
				  "a_string_bool": "true",
				  "a_bad_bool": "yee",
				  "a_duration": "7h",
				  "a_bad_duration": "hello",
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

	empty := struct{}{}
	err = UnmarshalSecrets(client, empty, "secret/application")
	assert.Equal(t, ErrValueInput, err)

	normal := struct {
		Hello string
	}{Hello: "hi!"}
	err = UnmarshalSecrets(client, &normal, "secret/application")
	assert.Equal(t, nil, err)
	assert.Equal(t, "hi!", normal.Hello)

	aFullPath := struct {
		Password string `vault_path:"secret/application/password" vault_key:"password"`
	}{}
	err = UnmarshalSecrets(client, &aFullPath, "secret/lol")
	assert.Equal(t, nil, err)
	assert.Equal(t, "nonstandard", aFullPath.Password)

	stdApex := struct {
		Password string `vault_path_key:"password"`
	}{}
	err = UnmarshalSecrets(client, &stdApex, "secret/application")
	assert.Equal(t, nil, err)
	assert.Equal(t, "standard", stdApex.Password)

	var embedded struct {
		Nested struct {
			PrivateKey string `vault_path_key:"password" vault_key:"private_key"`
		}
	}
	err = UnmarshalSecrets(client, &embedded, "secret/application")
	assert.Equal(t, nil, err)
	assert.Equal(t, "BEGIN PRIVATE KEY", embedded.Nested.PrivateKey)

	aBadString := struct {
		aBadString string `vault_path_key:"password" vault_key:"a_bad_string"`
	}{}
	err = UnmarshalSecrets(client, &aBadString, "secret/application")
	assert.NotNil(t, err)

	goodDuration := struct {
		ADuration time.Duration `vault_path_key:"password" vault_key:"a_duration"`
	}{}
	err = UnmarshalSecrets(client, &goodDuration, "secret/application")
	assert.Equal(t, nil, err)
	assert.Equal(t, time.Hour*7, goodDuration.ADuration)

	invalidDuration := struct {
		ADuration time.Duration `vault_path_key:"password" vault_key:"a_bad_duration"`
	}{}
	err = UnmarshalSecrets(client, &invalidDuration, "secret/application")
	assert.Equal(t, `time: invalid duration "hello"`, err.Error())

	aFloat := struct {
		AFloat float64 `vault_path_key:"password" vault_key:"a_float"`
	}{}
	err = UnmarshalSecrets(client, &aFloat, "secret/application")
	assert.Equal(t, nil, err)
	assert.Equal(t, 6.66, aFloat.AFloat)

	aStringFloat := struct {
		AFloat float64 `vault_path_key:"password" vault_key:"a_string_float"`
	}{}
	err = UnmarshalSecrets(client, &aStringFloat, "secret/application")
	assert.Equal(t, nil, err)
	assert.Equal(t, 6.66, aStringFloat.AFloat)

	aBadFloat := struct {
		aBadFloat float64 `vault_path_key:"password" vault_key:"a_bad_float"`
	}{}
	err = UnmarshalSecrets(client, &aBadFloat, "secret/application")
	assert.NotNil(t, err)

	anInteger := struct {
		AnInteger int64 `vault_path_key:"password" vault_key:"an_int"`
	}{}
	err = UnmarshalSecrets(client, &anInteger, "secret/application")
	assert.Equal(t, nil, err)
	assert.Equal(t, int64(12), anInteger.AnInteger)

	aStringInteger := struct {
		AStringInteger int64 `vault_path_key:"password" vault_key:"a_string_int"`
	}{}
	err = UnmarshalSecrets(client, &aStringInteger, "secret/application")
	assert.Equal(t, nil, err)
	assert.Equal(t, int64(12), aStringInteger.AStringInteger)

	aBadInt := struct {
		aBadInt int64 `vault_path_key:"password" vault_key:"a_bad_int"`
	}{}
	err = UnmarshalSecrets(client, &aBadInt, "secret/application")
	assert.NotNil(t, err)

	aBool := struct {
		ABool bool `vault_path_key:"password" vault_key:"a_bool"`
	}{}
	err = UnmarshalSecrets(client, &aBool, "secret/application")
	assert.Equal(t, nil, err)
	assert.Equal(t, true, aBool.ABool)

	aStringBool := struct {
		AStringBool bool `vault_path_key:"password" vault_key:"a_string_bool"`
	}{}
	err = UnmarshalSecrets(client, &aStringBool, "secret/application")
	assert.Equal(t, nil, err)
	assert.Equal(t, true, aStringBool.AStringBool)

	aBadBool := struct {
		aBadBool bool `vault_path_key:"password" vault_key:"a_bad_bool"`
	}{}
	err = UnmarshalSecrets(client, &aBadBool, "secret/application")
	assert.NotNil(t, err)

	aMisMatch := struct {
		AMismatch float64 `vault_path_key:"password" vault_key:"a_mismatch"`
	}{}
	err = UnmarshalSecrets(client, &aMisMatch, "secret/application")
	assert.Equal(t, `strconv.ParseFloat: parsing "7xL": invalid syntax`, err.Error())

	type x struct {
		Value string `vault_path_key:"password"`
	}
	aThing := struct {
		Thingy *x
	}{}
	err = UnmarshalSecrets(client, &aThing, "secret/application")
	if err != nil {
		fmt.Println(err)
	}
	assert.Equal(t, "standard", aThing.Thingy.Value)

	aPtrField := struct {
		Password *string `vault_path_key:"password"`
	}{}
	err = UnmarshalSecrets(client, &aPtrField, "secret/application")
	assert.Equal(t, nil, err)
	assert.Equal(t, "standard", *aPtrField.Password)
}
