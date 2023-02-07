build:
	@go build -o bin/packet-capture main.go

run: build
	@bin/packet-capture

run-tcp:
	sudo bin/packet-capture -protocol=tcp -interface=lo -matches 3
run-udp:
	sudo bin/packet-capture -protocol=udp -interface=lo -matches 3

run-netcat-tcp-server:
	while true; do nc -vl localhost 9090; done

run-netcat-udp-server:
	while true; do nc -vul localhost 9090; done

test:
	go test -v -race ./...
lint:
	golangci-lint run ./...
clean:
	@rm -rf bin/packet-capture

kind-up:
	kind create cluster --name packet-test --config kubernetes-kind/kind-config.yaml

kind-down:
	kind delete clusters packet-test

docker-build:
	docker build -f Dockerfile \
	--no-cache \
    --tag packet-capture:0.0.1 .

kind-import-image:
	kind load docker-image packet-capture:0.0.1 --name packet-test
