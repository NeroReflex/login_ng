# Build variables
BUILD_TYPE ?= release
TARGET ?= $(shell rustc -vV | grep "host" | sed 's/host: //')
ETC_DIR ?= etc

.PHONY_: install_login_ng-cli
install_login_ng-cli: target/$(TARGET)/$(BUILD_TYPE)/login_ng-cli
	install -D -m 755 target/$(TARGET)/$(BUILD_TYPE)/login_ng-cli $(PREFIX)/usr/bin/login_ng-cli
	install -D -m 644 rootfs/etc/pam.d/login_ng $(PREFIX)/$(ETC_DIR)/pam.d/login_ng
	install -D -m 644 rootfs/etc/pam.d/login_ng-autologin $(PREFIX)/$(ETC_DIR)/pam.d/login_ng-autologin
	install -D -m 644 rootfs/usr/lib/systemd/system/login_ng@.service $(PREFIX)/usr/lib/systemd/system/login_ng@.service
	install -D -m 644 rootfs/usr/lib/sysusers.d/login_ng.conf $(PREFIX)/usr/lib/sysusers.d/login_ng.conf
	mkdir -p -m 644 $(PREFIX)/usr/lib/login_ng

.PHONY_: install_login_ng-ctl
install_login_ng-ctl: target/$(TARGET)/$(BUILD_TYPE)/login_ng-ctl
	install -D -m 755 target/$(TARGET)/$(BUILD_TYPE)/login_ng-ctl $(PREFIX)/usr/bin/login_ng-ctl
	install -D -m 644 rootfs/etc/pam.d/login_ng-ctl $(PREFIX)/$(ETC_DIR)/pam.d/login_ng-ctl

.PHONY: install
install: install_login_ng-cli install_login_ng-ctl

.PHONY: build
build: fetch login_ng-gui/target/$(TARGET)/$(BUILD_TYPE)/login_ng-gui 

.PHONY: fetch
fetch: Cargo.lock
	cargo fetch --locked

target/$(TARGET)/$(BUILD_TYPE)/login_ng-cli: fetch
	cargo build --frozen --offline --all-features --bin login_ng-cli --$(BUILD_TYPE) --target=$(TARGET) --target-dir target

target/$(TARGET)/$(BUILD_TYPE)/login_ng-ctl: fetch
	cargo build --frozen --offline --all-features --bin login_ng-ctl --$(BUILD_TYPE) --target=$(TARGET) --target-dir target

.PHONY: clean
clean:
	cargo clean

.PHONY: all
all: build

.PHONY: deb
deb: fetch
	cargo-deb --all-features
