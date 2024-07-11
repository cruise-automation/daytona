#   Copyright 2019-present, Cruise LLC
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

VERSION=$(shell git describe --match 'v[0-9]*' --dirty='.m' --always --tags)
VERSION_TAG=$(VERSION:v%=%) # drop the v-prefix for docker images, per convention
PACKAGES=$(shell go list -mod=readonly ./...)
GOFILES=$(shell find . -type f -name '*.go'")
GO_LDFLAGS=-ldflags '-s -w -X main.version=${VERSION}'

.PHONY: entry
entry:
	@echo "These are your options:"
	@cat Makefile

.PHONY: check
check:
ifndef VERSION_TAG
	$(error VERSION_TAG must be set for image management)
endif

.PHONY: test
test:
	go test -race -cover -count=1 -v -mod=readonly ${PACKAGES}

.PHONY: coverage
coverage:
	go test -cover -count=1 -coverprofile=coverage.out -v ${PACKAGES}
	go tool cover -html=coverage.out

.PHONY: lint
lint:
	go vet -mod=readonly ${PACKAGES}
	gofmt -d -l ${GOFILES}
	test -z $(shell gofmt -d -l ${GOFILES})
	GO111MODULE=off go get -u golang.org/x/lint/golint
	$(shell go env GOPATH)/bin/golint -set_exit_status ${PACKAGES}

.PHONY: build
build:
	CGO_ENABLED=0 go build ${GO_LDFLAGS} -mod=readonly -o daytona cmd/daytona/main.go
	@command -v upx && upx daytona || echo "[INFO] No upx installed, not compressing."

.PHONY: image
image: check
	docker build -t daytona:${VERSION_TAG} .

.PHONY: push-image
push-image: check
	@if test "$(REGISTRY)" = "" ; then \
        echo "REGISTRY but must be set in order to continue"; \
        exit 1; \
	fi
	docker tag daytona:${VERSION_TAG} ${REGISTRY}/daytona:${VERSION_TAG}
	docker push ${REGISTRY}/daytona:${VERSION_TAG}
