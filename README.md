# Netassertv2-Packet-Sniffer

The `Netassertv2-Packet-Sniffer` is a Go program designed to sniff layer 4 (TCP or UDP) traffic and identify specific strings within it. It accepts the following environment variables:

| Environment Variable | Go Type | Default Value | Purpose |
| --- | --- | --- | --- |
| IFACE | string | eth0 | The network interface to listen on |
| SNAPLEN | int | 1024 | The packet snap length |
| PROMISC | bool | false | Should the network interface be set to Promiscuous mode |
| SEARCH_STRING | string | control-plane.io | The string to search in the TCP/UDP packet |
| PROTOCOL | string | tcp | The protocol we are interested in, can be tcp or udp |
| MATCHES | int | 3 | The number of matches after which the program will exit with a status code of 0 |
| TIMEOUT_SECONDS | int | 60 | The total duration during which we will capture the traffic. If we do not get enough matches (defined by `$MATCHES`) during this time, we exit with a status code of 1 |

If the specified number of matches are found within the defined timeout period, the program will exit with a status code of 0. If the required matches are not found within the given time, the program will exit with a status code of 1.

You can pull the latest Docker image from `docker.io/controlplane/netassertv2-packet-sniffer:latest`

## Libpacap Prerequisite

- This program uses the [Go Packet](https://github.com/google/gopacket) library for packet processing and uses C Bindings for libpcap. Therefore, you need to install libpacp dependencies for your OS to compile the program.

```bash
For Fedora/RHEL/CentOS
$ sudo dnf install libpcap-devel
For Debian/Ubuntu
$ sudo apt update && sudo apt install libpcap-dev -y

```

## Local testing

You can build and test the binary with the help of `netcat` server. To test the `TCP` protocol, run the following commands on different terminals:

In the first terminal run the packet sniffer, you will need to enter sudo password:

```bash
❯ make run-tcp
sudo bin/packet-capture -protocol=tcp -interface=lo -matches 3
2023-03-06T17:01:35.198Z	info	netassertv2-packet-sniffer/main.go:70	Working with following configuration:
{NetworkInterface:lo SnapLen:1024 Promisc:false SearchString:control-plane.io Protocol:tcp Environment:production NumberOfMatches:3 TimeoutSeconds:60}
	{"service": "packet-capture", "version": "development"}
2023-03-06T17:01:35.236Z	info	netassertv2-packet-sniffer/main.go:98	capturing "tcp" traffic on "lo" interface	{"service": "packet-capture", "version": "development"}
2023-03-06T17:01:35.236Z	info	netassertv2-packet-sniffer/main.go:101	starting to process packets	{"service": "packet-capture", "version": "development"}
...
....
```

This will launch the packet sniffer which will capture TCP traffic on local loopback adapater and search for string `control-plane.io` in the captured TCP packets.

In the second terminal run a `netcat` server the listens on port 12345:
```bash

❯ make run-netcat-tcp-server
while true; do nc -vl localhost 12345; done
Listening on view-localhost 12345

```

In the third terminal run a `netcat` client that will connect to the server on `localhost:12345` and send packet with payload `control-plane.io`

```bash

❯ make run-netcat-tcp-client
for i in `seq 1 4`; do echo 'control-plane.io' | nc -q 1 -v localhost 12345; done
Connection to localhost (127.0.0.1) 12345 port [tcp/*] succeeded!
Connection to localhost (127.0.0.1) 12345 port [tcp/*] succeeded!
Connection to localhost (127.0.0.1) 12345 port [tcp/*] succeeded!
Connection to localhost (127.0.0.1) 12345 port [tcp/*] succeeded!

```

The sniffer on the first terminal should exit with the following message:

```bash
2023-03-06T17:04:18.654Z	info	netassertv2-packet-sniffer/main.go:140	number of matches reached{"service": "packet-capture", "version": "development"}
```
