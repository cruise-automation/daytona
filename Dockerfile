#   Copyright 2019 GM Cruise LLC

#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at

#       http://www.apache.org/licenses/LICENSE-2.0

#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
ARG GO_VERSION=1.12
FROM golang:${GO_VERSION}-alpine AS builder
ENV GOFLAGS -mod=vendor
RUN apk --update add ca-certificates
WORKDIR /go/src/github.com/cruise-automation/daytona
COPY . .
RUN \
  CGO_ENABLED=0 \
  GOOS=linux \
  GOARCH=amd64 \
  go build -a -o daytona cmd/main.go

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /go/src/github.com/cruise-automation/daytona/daytona /
CMD ["/daytona"]
