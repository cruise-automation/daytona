package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"testing"
	"time"

	cfg "github.com/cruise-automation/daytona/pkg/config"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestInferRoleName(t *testing.T) {
	scenarios := []struct {
		TestName  string
		RoleName  string
		TestClaim map[string]interface{}
		Error     error
	}{
		{
			TestName: "1.21 claim",
			RoleName: "workloadX-1.21",
			TestClaim: map[string]interface{}{
				"kubernetes.io": map[string]interface{}{
					"serviceaccount": map[string]interface{}{
						"name": "workloadX-1.21",
					},
				},
			},
			Error: nil,
		},
		{
			TestName: "pre 1.21 claim",
			RoleName: "workloadX-pre",
			TestClaim: map[string]interface{}{
				"kubernetes.io/serviceaccount/service-account.name": "workloadX-pre",
			},
			Error: nil,
		},
		{
			TestName:  "invalid data",
			RoleName:  "",
			TestClaim: map[string]interface{}{},
			Error:     ErrInferRoleClaims,
		},
	}

	for _, scenario := range scenarios {
		token, err := NewTestToken(scenario.TestClaim)
		if err != nil {
			t.Fatalf("%s: failed to create test token: %s", scenario.TestName, err)
		}

		content := []byte(token)
		tmpfile, err := os.CreateTemp("", "k8jawn")
		if err != nil {
			t.Fatalf("%s: %s", scenario.TestName, err)
		}
		defer os.Remove(tmpfile.Name())

		if _, err := tmpfile.Write(content); err != nil {
			t.Fatalf("%s: %s", scenario.TestName, err)
		}
		if err := tmpfile.Close(); err != nil {
			t.Fatalf("%s: %s", scenario.TestName, err)
		}

		cfg := &cfg.Config{
			K8STokenPath: tmpfile.Name(),
		}
		role, err := inferVaultAuthRoleName(cfg)
		if err != scenario.Error {
			t.Fatalf("%s: expected %s, got %s", scenario.TestName, scenario.Error, err)
		}

		if role != scenario.RoleName {
			t.Fatalf("%s: expected role name %s, got %s", scenario.TestName, scenario.RoleName, role)
		}
	}
}

func NewTestToken(adtlClaims map[string]interface{}) (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %v", err)
	}

	stdClaims := jwt.Claims{
		Subject:   "somesvc",
		NotBefore: jwt.NewNumericDate(time.Now()),
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour * 1)),
		Audience:  jwt.Audience{"hello"},
	}

	var options jose.SignerOptions
	options.WithType("JWT").WithHeader("kid", "XX")
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, &options)
	if err != nil {
		return "", fmt.Errorf("failed to create the signer: %v", err)
	}

	raw, err := jwt.Signed(sig).Claims(stdClaims).Claims(adtlClaims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign the JWT: %v", err)
	}

	return raw, nil
}
