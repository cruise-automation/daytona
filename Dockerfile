FROM golang:1.13 AS builder
ENV CGO_ENABLED 0
ENV GO111MODULE on
ENV GOFLAGS -mod=vendor
WORKDIR /go/src/github.com/cruise-automation/daytona
COPY . .
RUN go build -o daytona -ldflags "-s -w" cmd/daytona/main.go

FROM alpine:latest as osdeps
RUN apk --update add ca-certificates tzdata zip
RUN zip -0 -r /zoneinfo.zip /usr/share/zoneinfo

FROM scratch
ENV ZONEINFO /zoneinfo.zip
COPY --from=osdeps /zoneinfo.zip /
COPY --from=osdeps /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /go/src/github.com/cruise-automation/daytona/daytona /
CMD ["/daytona"]
