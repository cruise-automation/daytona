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

package auth

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/cruise-automation/daytona/pkg/helpers/testhelpers"
	"github.com/stretchr/testify/assert"
)

func TestInvalidToken(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprintln(w, `{"errors":["permission denied"]}`)
	}))
	defer ts.Close()

	client, err := testhelpers.GetTestClient(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken(testToken)

	assert.Equal(t, false, checkToken(client))
}

func TestValidToken(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, testTokenLookupPayload)
	}))
	defer ts.Close()

	client, err := testhelpers.GetTestClient(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken(testToken)

	assert.Equal(t, true, checkToken(client))
}

func TestFileToken(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, testTokenLookupPayload)
	}))
	defer ts.Close()
	file, err := ioutil.TempFile(os.TempDir(), "daytona-test")
	if err != nil {
		t.Fatal(err)
	}

	err = ioutil.WriteFile(file.Name(), []byte(testToken), 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())

	client, err := testhelpers.GetTestClient(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, checkFileToken(client, file.Name()))
	assert.Equal(t, testToken, client.Token())
}
