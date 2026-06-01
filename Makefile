SHELL := /bin/bash
BINARY := wireguardc

.PHONY: build clean doctor probe run test bench gui app install-helper uninstall-helper

build:
	@go build -trimpath -ldflags "-s -w" -o $(BINARY) ./cmd/wireguardc

gui:
	@swift build -c release --package-path gui

app:
	@scripts/package_macos_app.sh

install-helper:
	@scripts/install_privileged_helper.sh

uninstall-helper:
	@scripts/uninstall_privileged_helper.sh

clean:
	@rm -f $(BINARY)

doctor: build
	@./wireguardc doctor

probe: build
	@./wireguardc probe

run: build
	@sudo ./wireguardc run

test: build
	@./wireguardc test

bench: build
	@./wireguardc bench
