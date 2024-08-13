FROM golang:1.22-alpine AS builder
COPY . /build
WORKDIR /build
RUN apk add --no-cache build-base libpcap-dev && \
    go mod download && \
    go test -race -v ./... && \
    # we need to enable CGO as we need to compile with libpcap bindings
    GO111MODULE=on CGO_ENABLED=1 GOOS=linux go build -v -o /packet-capture .

FROM alpine:3.18

COPY --from=builder /packet-capture /usr/bin/packet-capture

### we need to install libpcap-dev or else we will end up with the following errors:
### Error loading shared library libpcap.so.1: No such file or directory (needed by /usr/bin/packet-capture)
### Error relocating /usr/bin/packet-capture: pcap_set_tstamp_type: symbol not found\
#
### We can avoid to run as root by explicitly setting the CAP_NET_RAW capability to the sniffer binary.
### This capability is usually allowed by default by the container runtime but it can be explicitely
### provided using --cap-add NET_RAW (Docker) at runtime
RUN apk update && \
    apk upgrade && \
    apk add --no-cache libpcap-dev libcap && \
    chmod a+x /usr/bin/packet-capture && \
    /usr/sbin/setcap cap_net_raw+ep /usr/bin/packet-capture && \
    apk del libcap --no-cache

# user nobody, the "RunAsNonRoot" requires to have an uid
USER 65534
ENTRYPOINT [ "/usr/bin/packet-capture" ]
