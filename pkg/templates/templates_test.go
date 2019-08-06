package templates

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/api"

	"github.com/stretchr/testify/assert"
)

type TestSecretFetcher struct {
	Secrets map[string]map[string]interface{}
}

func (r *TestSecretFetcher) Read(secretPath string) (*api.Secret, error) {
	secret, ok := r.Secrets[secretPath]
	if !ok {
		return nil, fmt.Errorf("unable to locate secret: %s", secretPath)
	}

	fmt.Println(secret)
	return &api.Secret{Data: secret}, nil
}

func execute(t *testing.T, tmpl *DaytonaTemplate, input string) (string, error) {
	output := &bytes.Buffer{}
	parsed, err := tmpl.Parse(input)
	if err != nil {
		return "", err
	}
	err = parsed.Execute(output, nil)
	if err != nil {
		return "", err
	}
	return output.String(), nil
}

func testExecuteHelper(t *testing.T, tmpl *DaytonaTemplate, expected interface{}, input string) {
	res, err := execute(t, tmpl, input)
	if expectErr, ok := expected.(error); ok {
		assert.Contains(t, err.Error(), expectErr.Error())
		return
	}
	assert.Nil(t, err)
	assert.Equal(t, res, expected.(string))
}

func TestReadSecret(t *testing.T) {
	sf := &TestSecretFetcher{
		Secrets: map[string]map[string]interface{}{
			"/secret/data/ssssh": map[string]interface{}{
				"value": "don't tell anyone",
			},
		},
	}

	tmpl := New(sf)

	testExecuteHelper(t, tmpl, "Hello", "Hello")
	testExecuteHelper(t, tmpl, "Hello, don't tell anyone", `Hello, {{ (secret "/secret/data/ssssh").Data.value }}`)
	testExecuteHelper(t, tmpl, errors.New("unable to locate secret: doesn't exist"), `Hello, {{ (secret "doesn't exist").Data.value }}`)
}
