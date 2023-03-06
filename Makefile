build:
	@go build -o bin/packet-capture main.go

run: build
	@bin/packet-capture

run-tcp:
	sudo bin/packet-capture -protocol=tcp -interface=lo -matches 3
run-udp:
	sudo bin/packet-capture -protocol=udp -interface=lo -matches 3

run-netcat-tcp-server:
	while true; do nc -vl localhost 12345; done

run-netcat-tcp-client:
	for i in `seq 1 4`; do echo 'control-plane.io' | nc -q 1 -v localhost 12345; done

run-netcat-udp-server:
	while true; do nc -kvul localhost 12345; done

run-netcat-udp-client:
	for i in `seq 1 4`; do echo 'control-plane.io' | nc -q4 -vu localhost 12345; done

test:
	go test -v -race ./...
lint:
	golangci-lint run ./...
clean:
	@rm -rf bin/packet-capture

docker-build:
	docker build -f Dockerfile \
	--no-cache \
	--tag packet-capture:0.0.1 .

