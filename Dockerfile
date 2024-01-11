FROM golang:1.21
WORKDIR /go/src/github.com/nemosupremo/vault-statsd/
COPY ./ ./
RUN mkdir -p $GOPATH/pkg && \
	CGO_ENABLED=0 go build -ldflags "-X main.BuildTime=`date -u '+%Y-%m-%d_%I:%M:%S%p'` -X main.Version=`git -C ./ describe --abbrev=0 --tags HEAD`" -a -installsuffix cgo -o dist/vault-statsd ./

FROM scratch
COPY --from=0 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=0 /go/src/github.com/nemosupremo/vault-statsd/dist/vault-statsd /
# Create the /tmp directory
WORKDIR /tmp
WORKDIR /
CMD ["/vault-statsd"]