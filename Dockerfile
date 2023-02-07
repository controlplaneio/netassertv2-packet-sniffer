FROM golang:1.20-alpine AS builder
COPY . /build
WORKDIR /build
RUN apk add --no-cache build-base libpcap-dev && \
    go mod download && \
    go test -race -v ./... && \
    # we need to enable CGO as we need to compile with libpcap bindings
    GO111MODULE=on CGO_ENABLED=1 GOOS=linux go build -v -o /packet-capture . && \
    ls -ltr /packet-capture

FROM golang:1.20-alpine

# we need to install libpcap-dev or else we will end up with the following errors:
## Error loading shared library libpcap.so.1: No such file or directory (needed by /usr/bin/packet-capture)
## Error relocating /usr/bin/packet-capture: pcap_set_tstamp_type: symbol not found

COPY --from=builder /packet-capture /usr/bin/packet-capture

### We cannot run as non-root user at we need root privileges to
### capture traffic on the system
RUN apk update && \
    apk add --no-cache libpcap-dev && \
    chmod a+x /usr/bin/packet-capture

ENTRYPOINT [ "/usr/bin/packet-capture" ]
#ENTRYPOINT [ "/bin/sh" ]