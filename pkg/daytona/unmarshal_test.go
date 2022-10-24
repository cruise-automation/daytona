package daytona

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cruise-automation/daytona/pkg/helpers/testhelpers"
	"github.com/stretchr/testify/assert"
)

var testPayload = map[string]interface{}{
	"auth": nil,
	"data": map[string]interface{}{
		"value":          "standard",
		"password":       "nonstandard",
		"private_key":    "BEGIN PRIVATE KEY",
		"a_bad_string":   9,
		"an_int":         12,
		"a_string_int":   "12",
		"a_bad_int":      "xxx",
		"a_float":        6.66,
		"a_string_float": "6.66",
		"a_bad_float":    "xxx",
		"a_bool":         true,
		"a_string_bool":  "true",
		"a_bad_bool":     "yee",
		"a_duration":     "7h",
		"a_bad_duration": "hello",
		"a_mismatch":     "7xL",
	},
	"lease_duration": 3600,
	"lease_id":       "",
	"renewable":      false,
}

func generateMuliKeyPayload() (string, error) {
	b, err := json.Marshal(testPayload)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func TestUnmarshalSecretDataKeys(t *testing.T) {
	tp, err := generateMuliKeyPayload()
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/secret/application/password":
			fmt.Fprintln(w, tp)
		case "/v1/secret/top-level/API_KEY":
			fmt.Fprintln(w, `
				{
					"auth": null,
					"data": {
					  "value": "THIS_IS_MY_API_KEY"
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

	secret, err := NewSecretUnmarshler(WithClient(client))
	if err != nil {
		t.Fatal(err)
	}

	testData := testPayload["data"].(map[string]interface{})

	// generic type input validation
	empty := struct{}{}
	err = secret.Unmarshal(context.TODO(), "secret/applicaiton", empty)
	assert.Equal(t, ErrValueInput, err)

	var tst string
	err = secret.Unmarshal(context.TODO(), "secret/applicaiton", tst)
	assert.Equal(t, ErrValueInput, err)

	// unaffected fields
	normal := struct {
		Hello string
		Empty string
	}{Hello: "hi!"}
	err = secret.Unmarshal(context.TODO(), "secret/applicaiton", &normal)
	assert.Equal(t, nil, err)
	assert.Equal(t, "hi!", normal.Hello)
	assert.Equal(t, "", normal.Empty)

	conflictingTags := struct {
		Value string `vault_path_key:"password" vault_data_key:"value"`
	}{}
	err = secret.Unmarshal(context.TODO(), "secret/application", &conflictingTags)
	assert.Equal(t, nil, err)
	assert.Equal(t, "", conflictingTags.Value)

	aValue := struct {
		Value string `vault_data_key:"value"`
	}{}
	err = secret.Unmarshal(context.TODO(), "secret/application/password", &aValue)
	assert.Equal(t, nil, err)
	assert.Equal(t, testData["value"], aValue.Value)

	aFullPath := struct {
		Password string `vault_data_key:"password"`
	}{}
	err = secret.Unmarshal(context.TODO(), "secret/application/password", &aFullPath)
	assert.Equal(t, nil, err)
	assert.Equal(t, testData["password"], aFullPath.Password)

	var embedded struct {
		Nested struct {
			PrivateKey string `vault_data_key:"private_key"`
		}
	}
	err = secret.Unmarshal(context.TODO(), "secret/application/password", &embedded)
	assert.Equal(t, nil, err)
	assert.Equal(t, testData["private_key"], embedded.Nested.PrivateKey)

	aBadString := struct {
		aBadString string `vault_data_key:"a_bad_string"`
	}{}
	err = secret.Unmarshal(context.TODO(), "secret/application/password", &aBadString)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "expected a string")

	goodDuration := struct {
		ADuration time.Duration `vault_data_key:"a_duration"`
	}{}
	err = secret.Unmarshal(context.TODO(), "secret/application/password", &goodDuration)
	assert.Equal(t, nil, err)
	assert.Equal(t, time.Hour*7, goodDuration.ADuration)

	invalidDuration := struct {
		ADuration time.Duration `vault_data_key:"a_bad_duration"`
	}{}
	err = secret.Unmarshal(context.TODO(), "secret/application/password", &invalidDuration)
	assert.Equal(t, `time: invalid duration "hello"`, err.Error())

	aFloat := struct {
		AFloat float64 `vault_data_key:"a_float"`
	}{}
	err = secret.Unmarshal(context.TODO(), "secret/application/password", &aFloat)
	assert.Equal(t, nil, err)
	assert.Equal(t, testData["a_float"], aFloat.AFloat)

	aStringFloat := struct {
		AFloat float64 `vault_data_key:"a_string_float"`
	}{}
	err = secret.Unmarshal(context.TODO(), "secret/application/password", &aStringFloat)
	assert.Equal(t, nil, err)
	assert.Equal(t, testData["a_float"], aStringFloat.AFloat)

	aBadFloat := struct {
		aBadFloat float64 `vault_data_key:"a_bad_float"`
	}{}
	err = secret.Unmarshal(context.TODO(), "secret/application/password", &aBadFloat)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("parsing %q", testData["a_bad_float"]))

	anInteger := struct {
		AnInteger int `vault_data_key:"an_int"`
	}{}
	err = secret.Unmarshal(context.TODO(), "secret/application/password", &anInteger)
	assert.Equal(t, nil, err)
	assert.Equal(t, testData["an_int"], anInteger.AnInteger)

	aStringInteger := struct {
		AStringInteger int `vault_data_key:"a_string_int"`
	}{}
	err = secret.Unmarshal(context.TODO(), "secret/application/password", &aStringInteger)
	assert.Equal(t, nil, err)
	assert.Equal(t, testData["an_int"], aStringInteger.AStringInteger)

	aBadInt := struct {
		aBadInt int64 `vault_data_key:"a_bad_int"`
	}{}
	err = secret.Unmarshal(context.TODO(), "secret/application/password", &aBadInt)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("parsing %q", testData["a_bad_int"]))

	aBool := struct {
		ABool bool `vault_data_key:"a_bool"`
	}{}
	err = secret.Unmarshal(context.TODO(), "secret/application/password", &aBool)
	assert.Equal(t, nil, err)
	assert.Equal(t, testData["a_bool"], aBool.ABool)

	aStringBool := struct {
		AStringBool bool `vault_data_key:"a_string_bool"`
	}{}
	err = secret.Unmarshal(context.TODO(), "secret/application/password", &aStringBool)
	assert.Equal(t, nil, err)
	assert.Equal(t, testData["a_bool"], aStringBool.AStringBool)

	aBadBool := struct {
		aBadBool bool `vault_data_key:"a_bad_bool"`
	}{}
	err = secret.Unmarshal(context.TODO(), "secret/application/password", &aBadBool)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("parsing %q", testData["a_bad_bool"]))

	aMisMatch := struct {
		AMismatch float64 `vault_data_key:"a_mismatch"`
	}{}
	err = secret.Unmarshal(context.TODO(), "secret/application/password", &aMisMatch)
	assert.Equal(t, fmt.Sprintf(`strconv.ParseFloat: parsing %q: invalid syntax`, testData["a_mismatch"]), err.Error())

	type x struct {
		Value string `vault_data_key:"password"`
	}
	aStructWithPointer := struct {
		Thingy *x
	}{}
	err = secret.Unmarshal(context.TODO(), "secret/application/password", &aStructWithPointer)
	assert.Equal(t, nil, err)
	assert.Equal(t, testData["password"], aStructWithPointer.Thingy.Value)

	aPtrField := struct {
		Password *string `vault_data_key:"password"`
	}{}
	err = secret.Unmarshal(context.TODO(), "secret/application/password", &aPtrField)
	assert.Equal(t, nil, err)
	assert.Equal(t, testData["password"], *aPtrField.Password)
}

func TestUnmarshalSecretPathKeys(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/secret/top-level/API_KEY":
			fmt.Fprintln(w, `
				{
					"auth": null,
					"data": {
					  "value": "THIS_IS_MY_API_KEY"
					},
					"lease_duration": 3600,
					"lease_id": "",
					"renewable": false
				  }
				`)
		case "/v1/secret/top-level/SECRET_KEY":
			fmt.Fprintln(w, `
					{
						"auth": null,
						"data": {
						  "secret": "shhhh"
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

	secret, err := NewSecretUnmarshler(WithClient(client))
	if err != nil {
		t.Fatal(err)
	}

	pathKey := struct {
		Password string `vault_path_key:"API_KEY"`
	}{}
	err = secret.Unmarshal(context.TODO(), "secret/top-level", &pathKey)
	assert.Equal(t, nil, err)
	assert.Equal(t, "THIS_IS_MY_API_KEY", pathKey.Password)

	pathKeyAltDatKey := struct {
		Secret string `vault_path_key:"SECRET_KEY" vault_path_data_key:"secret"`
	}{}
	err = secret.Unmarshal(context.TODO(), "secret/top-level", &pathKeyAltDatKey)
	assert.Equal(t, nil, err)
	assert.Equal(t, "shhhh", pathKeyAltDatKey.Secret)
}
