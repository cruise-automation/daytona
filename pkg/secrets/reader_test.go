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

package secrets

import (
	"context"
	"errors"
	"fmt"
	"path"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
)

func TestParallelReaderBasic(t *testing.T) {
	apex := "secret/thing"

	keys := []string{"one", "two"}
	paths := make([]string, len(keys))

	for i := range keys {
		paths[i] = path.Join(apex, keys[i])
	}

	ctx := context.Background()

	logicalClient := &MockLogicalClient{
		FakeErr: nil,
	}
	parallelReader := NewParallelReader(ctx, logicalClient, 3)
	defer parallelReader.Close()

	def := &SecretDefinition{
		envkey:     "VAULT_SECRET_MEET",
		secretApex: apex,
		paths:      paths,
		secrets:    make(map[string]string),
	}

	err := parallelReader.ReadPaths(def)

	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 2, len(def.secrets))

	for i := range keys {
		v, ok := def.secrets[keys[i]]
		if !ok {
			t.Error("expected key to be present in secrets")
		}
		assert.Equal(t, "xxxx", v)
	}
}

func TestParallelReaderError(t *testing.T) {
	apex := "secret/thing"

	keys := []string{"one"}
	paths := make([]string, len(keys))
	errorMsg := "nope nope nope"

	for i := range keys {
		paths[i] = path.Join(apex, keys[i])
	}

	logicalClient := &MockLogicalClient{
		FakeErr: errors.New("nope nope nope"),
	}
	ctx := context.Background()

	parallelReader := NewParallelReader(ctx, logicalClient, 3)
	defer parallelReader.Close()

	def := &SecretDefinition{
		envkey:     "VAULT_SECRET_MEET",
		secretApex: apex,
		paths:      paths,
		secrets:    make(map[string]string),
	}

	err := parallelReader.ReadPaths(def)
	assert.EqualError(t, err, fmt.Sprintf("failed to retrieve secret path %s: %s", paths[0], errorMsg))
}

// MockLogicalClient is an implementation that satisfies LogicalClient interface
type MockLogicalClient struct {
	FakeErr error
}

// Read returns a mock secret response for a given path
func (m *MockLogicalClient) Read(path string) (*api.Secret, error) {
	return &api.Secret{
		RequestID: path,

		LeaseID:       "abc",
		LeaseDuration: 600,
		Renewable:     true,

		Data: map[string]interface{}{
			"value": "xxxx",
		},

		Warnings: []string{},
	}, m.FakeErr
}
