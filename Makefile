# Build variables
BUILD_TYPE ?= release
TARGET ?= $(shell rustc -vV | grep "host" | sed 's/host: //')
ETC_DIR ?= etc

.PHONY_: install_login_ng-cli
install_login_ng-cli: login_ng-cli/target/$(TARGET)/$(BUILD_TYPE)/login_ng-cli
	install -D -m 755 login_ng-cli/target/$(TARGET)/$(BUILD_TYPE)/login_ng-cli $(PREFIX)/usr/bin/login_ng-cli
	install -D -m 644 rootfs/etc/pam.d/login_ng $(PREFIX)/$(ETC_DIR)/pam.d/login_ng
	install -D -m 644 rootfs/etc/pam.d/login_ng-autologin $(PREFIX)/$(ETC_DIR)/pam.d/login_ng-autologin
	install -D -m 644 rootfs/usr/lib/systemd/system/login_ng@.service $(PREFIX)/usr/lib/systemd/system/login_ng@.service
	install -D -m 644 rootfs/usr/lib/sysusers.d/login_ng.conf $(PREFIX)/usr/lib/sysusers.d/login_ng.conf
	mkdir -p -m 644 $(PREFIX)/usr/lib/login_ng

.PHONY_: install_login_ng-ctl
install_login_ng-ctl: login_ng-ctl/target/$(TARGET)/$(BUILD_TYPE)/login_ng-ctl
	install -D -m 755 login_ng-ctl/target/$(TARGET)/$(BUILD_TYPE)/login_ng-ctl $(PREFIX)/usr/bin/login_ng-ctl
	install -D -m 644 rootfs/etc/pam.d/login_ng-ctl $(PREFIX)/$(ETC_DIR)/pam.d/login_ng-ctl

.PHONY_: install_login_ng-gui
install_login_ng-gui: login_ng-gui/target/$(TARGET)/$(BUILD_TYPE)/login_ng-gui
	install -D -m 755 login_ng-gui/target/$(TARGET)/$(BUILD_TYPE)/login_ng-gui $(PREFIX)/usr/bin/login_ng-gui

.PHONY_: install_login_ng-session
install_login_ng-session: login_ng-session/target/$(TARGET)/$(BUILD_TYPE)/login_ng-session login_ng-session/target/$(TARGET)/$(BUILD_TYPE)/login_ng-sessionctl
	install -D -m 755 login_ng-session/target/$(TARGET)/$(BUILD_TYPE)/login_ng-session $(PREFIX)/usr/bin/login_ng-session
	install -D -m 755 login_ng-session/target/$(TARGET)/$(BUILD_TYPE)/login_ng-sessionctl $(PREFIX)/usr/bin/login_ng-sessionctl
	install -D -m 755 rootfs/usr/share/wayland-sessions/login_ng-session.desktop $(PREFIX)/usr/share/wayland-sessions/login_ng-session.desktop
	install -D -m 755 rootfs/usr/bin/start-login_ng-session $(PREFIX)/usr/bin/start-login_ng-session

.PHONY_: install_pam_login_ng
install_pam_login_ng: pam_login_ng/target/$(TARGET)/$(BUILD_TYPE)/pam_login_ng-service pam_login_ng/target/$(TARGET)/$(BUILD_TYPE)/libpam_login_ng.so
	install -D -m 755 pam_login_ng/target/$(TARGET)/$(BUILD_TYPE)/pam_login_ng-service $(PREFIX)/usr/bin/pam_login_ng-service
	install -D -m 755 pam_login_ng/target/$(TARGET)/$(BUILD_TYPE)/libpam_login_ng.so $(PREFIX)/usr/lib/security/pam_login_ng.so
	install -D -m 644 rootfs/usr/lib/systemd/system/pam_login_ng.service $(PREFIX)/usr/lib/systemd/system/pam_login_ng.service

.PHONY_: install_sessionexec
install_sessionexec: sessionexec/target/$(TARGET)/$(BUILD_TYPE)/sessionexec
	install -D -m 755 sessionexec/target/$(TARGET)/$(BUILD_TYPE)/sessionexec $(PREFIX)/usr/bin/sessionexec
	install -D -m 755 rootfs/usr/lib/sessionexec/session-return.sh $(PREFIX)/usr/lib/sessionexec/session-return.sh
	install -D -m 755 rootfs/usr/lib/os-session-select $(PREFIX)/usr/lib/os-session-select
	install -D -m 644 rootfs/usr/lib/login_ng-session/steamdeck.service $(PREFIX)/usr/lib/login_ng-session/steamdeck.service
	install -D -m 644 rootfs/usr/lib/login_ng-session/default.service $(PREFIX)/usr/lib/login_ng-session/default.service
	install -D -m 755 rootfs/usr/share/wayland-sessions/game-mode.desktop $(PREFIX)/usr/share/wayland-sessions/game-mode.desktop
	install -D -m 755 rootfs/usr/share/applications/org.sessionexec.session-return.desktop $(PREFIX)/usr/share/applications/org.sessionexec.session-return.desktop
	rm -f $(PREFIX)/usr/share/wayland-sessions/default.desktop
	ln -s game-mode.desktop $(PREFIX)/usr/share/wayland-sessions/default.desktop

.PHONY: install
install: install_login_ng-cli install_login_ng-ctl install_login_ng-session install_pam_login_ng install_sessionexec install_login_ng-gui

.PHONY: build
build: fetch login_ng-gui/target/$(TARGET)/$(BUILD_TYPE)/login_ng-gui 

.PHONY: fetch
fetch: Cargo.lock
	cargo fetch --locked

sessionexec/target/$(TARGET)/$(BUILD_TYPE)/sessionexec: fetch
	cd sessionexec && cargo build --frozen --offline --all-features --$(BUILD_TYPE) --target=$(TARGET) --target-dir target

login_ng-cli/target/$(TARGET)/$(BUILD_TYPE)/login_ng-cli: fetch
	cd login_ng-cli && cargo build --frozen --offline --all-features --$(BUILD_TYPE) --target=$(TARGET) --target-dir target

login_ng-ctl/target/$(TARGET)/$(BUILD_TYPE)/login_ng-ctl: fetch
	cd login_ng-ctl && cargo build --frozen --offline --all-features --$(BUILD_TYPE) --target=$(TARGET) --target-dir target

login_ng-gui/target/$(TARGET)/$(BUILD_TYPE)/login_ng-gui: fetch
	cd login_ng-gui && cargo build --frozen --offline --all-features --$(BUILD_TYPE) --target=$(TARGET) --target-dir target

login_ng-session/target/$(TARGET)/$(BUILD_TYPE)/login_ng-session: fetch
	cd login_ng-session && cargo build --frozen --offline --all-features --$(BUILD_TYPE) --target=$(TARGET) --target-dir target

login_ng-session/target/$(TARGET)/$(BUILD_TYPE)/login_ng-sessionctl: fetch
	cd login_ng-session && cargo build --frozen --offline --all-features --$(BUILD_TYPE) --target=$(TARGET) --target-dir target --bin login_ng-sessionctl

pam_login_ng/target/$(TARGET)/$(BUILD_TYPE)/pam_login_ng-service: pam_login_ng/target/$(TARGET)/$(BUILD_TYPE)/libpam_login_ng.so
	cd pam_login_ng && cargo build --frozen --offline --all-features --$(BUILD_TYPE) --bin pam_login_ng-service --target=$(TARGET) --target-dir target

pam_login_ng/target/$(TARGET)/$(BUILD_TYPE)/libpam_login_ng.so: fetch
	cd pam_login_ng && cargo build --frozen --offline --all-features --$(BUILD_TYPE) --lib --target=$(TARGET) --target-dir target

.PHONY: clean
clean:
	cargo clean
	rm -rf login_ng/target
	rm -rf login_ng-cli/target
	rm -rf login_ng-gui/target
	rm -rf login_ng-ctl/target
	rm -rf login_ng-session/target
	rm -rf pam_login_ng-common/target
	rm -rf pam_login_ng/target
	rm -rf sessionexec/target

.PHONY: all
all: build

.PHONY: deb
deb: fetch
	cd sessionexec && cargo-deb --all-features
	cd login_ng-cli && cargo-deb --all-features
	cd login_ng-ctl && cargo-deb --all-features
	cd login_ng-gui && cargo-deb --all-features
	cd login_ng-session && cargo-deb --all-features
	cd pam_login_ng && cargo-deb --all-features
