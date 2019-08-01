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
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
)

type TestParameters struct {
	NumKeys    int
	NumWorkers int
	Err        error
}

func TestParallelReader(t *testing.T) {
	tests := []TestParameters{
		TestParameters{
			NumKeys:    0,
			NumWorkers: 1,
			Err:        nil,
		},
		TestParameters{
			NumKeys:    1,
			NumWorkers: 1,
			Err:        nil,
		},
		TestParameters{
			NumKeys:    5,
			NumWorkers: 1,
			Err:        nil,
		},
		TestParameters{
			NumKeys:    2,
			NumWorkers: 2,
			Err:        nil,
		},
		TestParameters{
			NumKeys:    1,
			NumWorkers: 2,
			Err:        nil,
		},
		TestParameters{
			NumKeys:    5,
			NumWorkers: 5,
			Err:        nil,
		},
		TestParameters{
			NumKeys:    0,
			NumWorkers: 5,
			Err:        nil,
		},
		TestParameters{
			NumKeys:    5,
			NumWorkers: 5,
			Err:        fmt.Errorf("mock error"),
		},
	}

	for _, testParameters := range tests {
		testParallelReadIteration(t, testParameters)
	}
}

func testParallelReadIteration(t *testing.T, testParameters TestParameters) {
	expectedSecretResults := getExpectedSecretResults(testParameters)

	ctx := context.Background()
	logicalClient := &MockLogicalClient{
		FakeErr: testParameters.Err,
	}

	parallelReader := NewParallelReader(ctx, logicalClient, testParameters.NumWorkers)
	defer parallelReader.Close()

	for i := 0; i < testParameters.NumKeys; i++ {
		parallelReader.AsyncRequestKeyPath(fmt.Sprintf("fake/path/key%d", i))
	}

	secretResults := make(map[string]*SecretResult)
	for i := 0; i < testParameters.NumKeys; i++ {
		secretResult := parallelReader.ReadSecretResult()
		secretResults[secretResult.KeyPath] = secretResult
	}

	assert.Equal(t, len(secretResults), testParameters.NumKeys)
	for expectedKeyPath, expectedSecretResult := range expectedSecretResults {
		secretResult, exists := secretResults[expectedKeyPath]
		assert.Equal(t, true, exists)

		assert.Equal(t, expectedSecretResult.KeyPath, secretResult.KeyPath)
		assert.Equal(t, expectedSecretResult.Err, secretResult.Err)

		assert.Equal(t, expectedSecretResult.Secret.RequestID, secretResult.Secret.RequestID)
		assert.Equal(t, expectedSecretResult.Secret.LeaseID, secretResult.Secret.LeaseID)
		assert.Equal(t, expectedSecretResult.Secret.LeaseDuration, secretResult.Secret.LeaseDuration)
		assert.Equal(t, expectedSecretResult.Secret.Renewable, secretResult.Secret.Renewable)
		assert.Equal(t, expectedSecretResult.Secret.Data, secretResult.Secret.Data)
		assert.Equal(t, expectedSecretResult.Secret.Warnings, secretResult.Secret.Warnings)
	}
}

func getExpectedSecretResults(testParameters TestParameters) map[string]*SecretResult {
	secretResults := make(map[string]*SecretResult)
	for i := 0; i < testParameters.NumKeys; i++ {
		keyPath := fmt.Sprintf("fake/path/key%d", i)

		secret := &api.Secret{
			RequestID: keyPath,

			LeaseID:       "abc",
			LeaseDuration: 600,
			Renewable:     true,

			Data: map[string]interface{}{
				"key": keyPath,
			},

			Warnings: []string{},
		}

		secretResult := &SecretResult{
			KeyPath: keyPath,
			Secret:  secret,
			Err:     testParameters.Err,
		}

		secretResults[secretResult.KeyPath] = secretResult
	}

	return secretResults
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
			"key": path,
		},

		Warnings: []string{},
	}, m.FakeErr
}
