#!/usr/bin/env bash
set -euxo pipefail

service_name=sftpguy

./sftpguy_amd64 \
	-maxsize 69793218560 \
    -debug -logfile /var/log/sftpguy.log \
	-dir /volume1/public \
    -db.path /var/lib/sftpguy/sftp.db \
	-caid.db /volume1/caid/caid.db \
	-noauth \
    -port 2222 -admin.sftp -admin.http :9911 \
	-install \
	-install.explorer ./explorerv2_amd64 \
	-install.explorer.port 9112 \
	-install.explorer.log /var/log/nk-explorer.log \
	-install.explorer.maxsize 10000 \
	-install.explorer.header header.html

systemctl stop "$service_name.service" "$service_name-explorer.service" || true
systemctl disable "$service_name.service" "$service_name-explorer.service" || true
rm -f "/etc/systemd/system/multi-user.target.wants/$service_name.service" "/etc/systemd/system/multi-user.target.wants/$service_name-explorer.service"
systemctl daemon-reload
systemctl reset-failed "$service_name.service" "$service_name-explorer.service" || true
systemctl enable "$service_name.socket" "$service_name-explorer-events.socket" "$service_name-explorer.socket"
