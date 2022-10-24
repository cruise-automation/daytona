package daytona

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/hashicorp/vault/api"
)

var testToken = "THIS IS MY TOKEN"

func TestOptionsWithClient(t *testing.T) {
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	client.SetToken(testToken)

	u, err := NewSecretUnmarshler(WithClient(client))
	if err != nil {
		t.Fatal(err)
	}

	if u.client.Token() != testToken {
		// we purposely don't log api.Client.Token() in the
		// unlikely event we pickup a production token
		t.Fatalf("WithClient options is not working. exptected token %s, got something else...", testToken)
	}
}

func TestOptionsWithTokenString(t *testing.T) {
	u, err := NewSecretUnmarshler(WithTokenString(testToken))
	if err != nil {
		t.Fatal(err)
	}

	if u.client.Token() != testToken {
		// we purposely don't log api.Client.Token() in the
		// unlikely event we pickup a production token
		t.Fatalf("WithTokenString options is not working. exptected token %s, got something else...", testToken)
	}
}

func TestOptionsWithTokenFile(t *testing.T) {
	fileTokenContents := "THIS IS MY FILE TOKEN"
	file, err := ioutil.TempFile("", "test-vault-token")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(file.Name())

	_, err = file.Write([]byte(fileTokenContents))
	if err != nil {
		t.Fatal(err)
	}

	u, err := NewSecretUnmarshler(WithTokenFile(file.Name()))
	if err != nil {
		t.Fatal(err)
	}

	if u.client.Token() != fileTokenContents {
		// we purposely don't log api.Client.Token() in the
		// unlikely event we pickup a production token
		t.Fatalf("WithTokenFile options is not working. exptected token %s, got something else...", testToken)
	}
}
