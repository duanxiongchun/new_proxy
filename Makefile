# Makefile for new_proxy packaging

VERSION = 5.0.0
ARCH ?= $(shell dpkg --print-architecture 2>/dev/null || echo amd64)
DEB_DIR = target/deb-pkg
DEB_FILE = target/new-proxy_$(VERSION)_$(ARCH).deb

.PHONY: all build package clean

all: build

build:
	cargo build --release --bins

package: build
	@echo "Building Debian package structure..."
	rm -rf $(DEB_DIR)
	mkdir -p $(DEB_DIR)/DEBIAN
	mkdir -p $(DEB_DIR)/usr/bin
	mkdir -p $(DEB_DIR)/lib/systemd/system
	mkdir -p $(DEB_DIR)/etc/new_proxy

	# Copy binaries
	cp target/release/new_proxy $(DEB_DIR)/usr/bin/new_proxy
	cp target/release/new-proxy-cli $(DEB_DIR)/usr/bin/new-proxy-cli
	chmod 755 $(DEB_DIR)/usr/bin/new_proxy
	chmod 755 $(DEB_DIR)/usr/bin/new-proxy-cli

	# Copy systemd service template
	cp script/new_proxy@.service $(DEB_DIR)/lib/systemd/system/new_proxy@.service
	chmod 644 $(DEB_DIR)/lib/systemd/system/new_proxy@.service

	# Copy example configs
	cp conf/server.conf $(DEB_DIR)/etc/new_proxy/server.conf.example
	cp conf/client.conf $(DEB_DIR)/etc/new_proxy/client.conf.example
	chmod 600 $(DEB_DIR)/etc/new_proxy/server.conf.example
	chmod 600 $(DEB_DIR)/etc/new_proxy/client.conf.example

	# Write control file
	echo "Package: new-proxy" > $(DEB_DIR)/DEBIAN/control
	echo "Version: $(VERSION)" >> $(DEB_DIR)/DEBIAN/control
	echo "Section: net" >> $(DEB_DIR)/DEBIAN/control
	echo "Priority: optional" >> $(DEB_DIR)/DEBIAN/control
	echo "Architecture: $(ARCH)" >> $(DEB_DIR)/DEBIAN/control
	echo "Depends: libc6, iproute2, iptables" >> $(DEB_DIR)/DEBIAN/control
	echo "Maintainer: Xiongchun Duan <duanxiongchun@bytedance.com>" >> $(DEB_DIR)/DEBIAN/control
	echo "Description: Hybrid Secure Proxy Gateway (WireGuard L3 + QUIC L4 Mux)" >> $(DEB_DIR)/DEBIAN/control

	# Build deb package
	dpkg-deb --build $(DEB_DIR) $(DEB_FILE)
	@echo "Debian package created successfully: $(DEB_FILE)"

clean:
	cargo clean
	rm -rf target/deb-pkg target/*.deb
