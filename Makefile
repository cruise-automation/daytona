#   Copyright 2019 GM Cruise LLC
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
VERSION=1.0.0
PACKAGES=$(shell go list ./... | grep -v /vendor/)
GOFILES=$(shell find . -type f -name '*.go' -not -path "./vendor/*")

.PHONY: entry test lint build image push-image

entry:
	@echo "These are your options:"
	@cat Makefile

check:
ifndef VERSION
	$(error VERSION must be set for image management)
endif

test:
	go test -cover -count=1 -v ${PACKAGES}

lint:
	go vet ${PACKAGES}
	gofmt -d -l ${GOFILES}

build:
	go build -a -o daytona cmd/main.go

image: check
	docker build -t daytona:${VERSION} .

push-image: check
	@if test "$(REGISTRY)" = "" ; then \
        echo "REGISTRY but must be set in order to continue"; \
        exit 1; \
	fi
	docker tag daytona:${VERSION} ${REGISTRY}/daytona:${VERSION}
	docker push ${REGISTRY}/daytona:${VERSION}
