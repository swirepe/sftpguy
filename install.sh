#!/usr/bin/env bash
set -euxo pipefail

service_name=sftpguy

./sftpguy_amd64 \
	-maxsize 69793218560 \
    -debug -logfile /volume1/caid/sftpguy.log \
	-dir /volume1/public \
    -db.path /volume1/caid/sftp.db \
	-caid.db /volume1/caid/caid.db \
	-dir.max 1000000 \
	-noauth \
	-geoip.dir /volume1/caid/geoip \
    -port 2222 -admin.sftp -admin.http :9911 \
	-install \
	-install.explorer ./explorerv2_amd64 \
	-install.explorer.port 9112 \
	-install.explorer.log /volume1/caid/nk-explorer.log \
	-install.explorer.maxsize 10000 \
	-install.explorer.header header.html

#systemctl stop "$service_name.service" "$service_name-explorer.service" || true
#systemctl disable "$service_name.service" "$service_name-explorer.service" || true
#rm -f "/etc/systemd/system/multi-user.target.wants/$service_name.service" "/etc/systemd/system/multi-user.target.wants/$service_name-explorer.service"
#systemctl daemon-reload
#systemctl reset-failed "$service_name.service" "$service_name-explorer.service" || true
#systemctl enable "$service_name.socket" "$service_name-explorer-events.socket" "$service_name-explorer.socket"
