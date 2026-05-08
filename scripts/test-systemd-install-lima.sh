#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

instance="${LIMA_INSTANCE:-sftpguy-install-test}"
template="${LIMA_TEMPLATE:-template://ubuntu-lts}"
service_name="${SERVICE_NAME:-sftpguy-install-test}"
service_user="${SERVICE_USER:-sftpguytest}"
service_group="${SERVICE_GROUP:-sftpguytest}"
sftp_port="${SFTP_PORT:-22222}"
explorer_port="${EXPLORER_PORT:-18080}"
with_explorer="${WITH_EXPLORER:-1}"
run_test_client="${RUN_TEST_CLIENT:-1}"
keep_install="${KEEP_INSTALL:-0}"
destroy_lima="${DESTROY_LIMA:-0}"
server_extra_args_raw="${SERVER_EXTRA_ARGS:-}"
test_client_args_raw="${TEST_CLIENT_ARGS:-}"
server_extra_args=()
test_client_args=()

build_dir=""
created_instance=0

usage() {
	cat <<'EOF'
Usage: scripts/test-systemd-install-lima.sh

Smoke-test sftpguy's -install systemd path inside a Lima VM.

Environment:
  LIMA_INSTANCE       Lima instance to use or create (default: sftpguy-install-test)
  LIMA_TEMPLATE       Template used when creating the instance (default: template://ubuntu-lts)
  SERVICE_NAME        systemd service/unit prefix (default: sftpguy-install-test)
  SERVICE_USER        service user created by -install.ensure (default: sftpguytest)
  SERVICE_GROUP       service group created by -install.ensure (default: sftpguytest)
  SFTP_PORT           guest TCP port for the SFTP socket (default: 22222)
  EXPLORER_PORT       guest TCP port for the explorer socket (default: 18080)
  WITH_EXPLORER       build and install cmd/explorer too: 1 or 0 (default: 1)
  RUN_TEST_CLIENT     run the standalone SFTP client suite too: 1 or 0 (default: 1)
  SERVER_EXTRA_ARGS   extra sftpguy flags forwarded into the installed service
  TEST_CLIENT_ARGS    extra flags passed to the standalone test client
  KEEP_INSTALL        leave systemd units and /var/lib data in the VM: 1 or 0 (default: 0)
  DESTROY_LIMA        delete a VM this script created after the run: 1 or 0 (default: 0)

Examples:
  scripts/test-systemd-install-lima.sh
  LIMA_INSTANCE=default WITH_EXPLORER=0 scripts/test-systemd-install-lima.sh
  SERVER_EXTRA_ARGS="-admin.sftp" KEEP_INSTALL=1 scripts/test-systemd-install-lima.sh
  RUN_TEST_CLIENT=0 SERVER_EXTRA_ARGS="-noauth -admin.sftp" scripts/test-systemd-install-lima.sh
  KEEP_INSTALL=1 scripts/test-systemd-install-lima.sh
EOF
}

log() {
	printf '\n==> %s\n' "$*"
}

die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

validate_name() {
	local label="$1"
	local value="$2"
	[[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die "$label must match [A-Za-z0-9][A-Za-z0-9_.-]*: $value"
}

validate_port() {
	local label="$1"
	local value="$2"
	[[ "$value" =~ ^[0-9]+$ ]] || die "$label must be an integer: $value"
	((value >= 1 && value <= 65535)) || die "$label must be between 1 and 65535: $value"
}

limactl_quiet() {
	limactl --tty=false "$@"
}

guest() {
	limactl_quiet shell "$instance" "$@"
}

guest_bash() {
	limactl_quiet shell "$instance" bash -lc "$1"
}

server_has_flag() {
	local want="$1"
	local arg
	for arg in "${server_extra_args[@]}"; do
		case "$arg" in
			"$want" | "$want"=*)
				return 0
				;;
		esac
	done
	return 1
}

unit_names() {
	printf '%s\n' \
		"${service_name}.service" \
		"${service_name}.socket" \
		"${service_name}-explorer-events.socket" \
		"${service_name}-explorer.service" \
		"${service_name}-explorer.socket"
}

cleanup_guest_install() {
	log "Cleaning systemd install from Lima instance $instance"
	local units
	units="$(unit_names | tr '\n' ' ')"
	guest_bash "sudo systemctl disable --now $units >/dev/null 2>&1 || true"
	guest_bash "for unit in $units; do sudo rm -f \"/etc/systemd/system/\$unit\"; done"
	guest sudo systemctl daemon-reload
	guest sudo systemctl reset-failed
	guest sudo rm -rf "/var/lib/${service_name}" "/run/${service_name}"
}

cleanup() {
	local status=$?
	if [[ -n "$build_dir" ]]; then
		rm -rf "$build_dir"
	fi
	if [[ "$keep_install" != "1" ]]; then
		cleanup_guest_install || true
	fi
	if [[ "$created_instance" == "1" && "$destroy_lima" == "1" ]]; then
		log "Deleting Lima instance $instance"
		limactl_quiet delete -f "$instance" || true
	fi
	exit "$status"
}

diagnose() {
	local status=$?
	if [[ "$status" == "0" ]]; then
		return
	fi
	printf '\nTest failed. Recent systemd status and logs from %s:\n' "$instance" >&2
	guest_bash "sudo systemctl --no-pager -l status '${service_name}.service' '${service_name}.socket' '${service_name}-explorer-events.socket' '${service_name}-explorer.service' '${service_name}-explorer.socket' || true" >&2 || true
	guest_bash "sudo journalctl --no-pager -n 120 -u '${service_name}.service' -u '${service_name}.socket' -u '${service_name}-explorer-events.socket' -u '${service_name}-explorer.service' -u '${service_name}-explorer.socket' || true" >&2 || true
	return "$status"
}

start_lima() {
	if limactl_quiet list -q | grep -qx "$instance"; then
		log "Starting existing Lima instance $instance"
		limactl_quiet start "$instance"
	else
		log "Creating Lima instance $instance from $template"
		limactl_quiet start --name="$instance" --cpus=2 --memory=2 --disk=20 "$template"
		created_instance=1
	fi
}

guest_goarch() {
	local arch
	arch="$(guest uname -m | tr -d '\r')"
	case "$arch" in
		x86_64 | amd64)
			printf 'amd64\n'
			;;
		aarch64 | arm64)
			printf 'arm64\n'
			;;
		*)
			die "unsupported Lima guest architecture: $arch"
			;;
	esac
}

build_binaries() {
	local goarch="$1"
	build_dir="$(mktemp -d "${TMPDIR:-/tmp}/sftpguy-lima-install.XXXXXX")"

	log "Building Linux/$goarch sftpguy binary"
	(
		cd "$repo_root"
		CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath -o "$build_dir/sftpguy" .
	)

	if [[ "$with_explorer" == "1" ]]; then
		log "Building Linux/$goarch explorer binary"
		(
			cd "$repo_root"
			CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath -o "$build_dir/sftpguy-explorer" ./cmd/explorer
		)
	fi

	if [[ "$run_test_client" == "1" ]]; then
		log "Building Linux/$goarch standalone test client"
		(
			cd "$repo_root"
			CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -tags testclient -trimpath -o "$build_dir/sftpguy-test-client" test_client.go
		)
	fi
}

copy_binaries() {
	local guest_dir="/tmp/sftpguy-install-test"
	log "Copying binaries into Lima instance"
	guest rm -rf "$guest_dir"
	guest mkdir -p "$guest_dir"
	limactl_quiet copy "$build_dir/sftpguy" "${instance}:${guest_dir}/sftpguy"
	if [[ "$with_explorer" == "1" ]]; then
		limactl_quiet copy "$build_dir/sftpguy-explorer" "${instance}:${guest_dir}/sftpguy-explorer"
	fi
	if [[ "$run_test_client" == "1" ]]; then
		limactl_quiet copy "$build_dir/sftpguy-test-client" "${instance}:${guest_dir}/sftpguy-test-client"
	fi
	guest chmod +x "${guest_dir}/sftpguy"
	if [[ "$with_explorer" == "1" ]]; then
		guest chmod +x "${guest_dir}/sftpguy-explorer"
	fi
	if [[ "$run_test_client" == "1" ]]; then
		guest chmod +x "${guest_dir}/sftpguy-test-client"
	fi
}

run_install() {
	local guest_dir="/tmp/sftpguy-install-test"
	local install_dir="/var/lib/${service_name}"
	local explorer_args=()

	if [[ "$with_explorer" == "1" ]]; then
		explorer_args=(
			-install.explorer "${guest_dir}/sftpguy-explorer"
			-install.explorer.port "$explorer_port"
			-install.explorer.log "${install_dir}/explorer.log"
		)
	fi

	log "Running -install in Lima"
	guest sudo "${guest_dir}/sftpguy" \
		-install \
		-install.service "$service_name" \
		-install.user "$service_user" \
		-install.group "$service_group" \
		-install.ensure=true \
		"${explorer_args[@]}" \
		-port "$sftp_port" \
		-dir "${install_dir}/uploads" \
		-db.path "${install_dir}/sftp.db" \
		-logfile "${install_dir}/sftpguy.log" \
		-hostkey "${install_dir}/id_ed25519" \
		-admin.keys "${install_dir}/admin_keys.txt" \
		-blacklist "${install_dir}/blacklist.txt" \
		-whitelist "${install_dir}/whitelist.txt" \
		-bad "${install_dir}/bad_files.txt" \
		-contrib 1024 \
		"${server_extra_args[@]}"
}

verify_units() {
	local units
	units=(
		"/etc/systemd/system/${service_name}.service"
		"/etc/systemd/system/${service_name}.socket"
		"/etc/systemd/system/${service_name}-explorer-events.socket"
	)
	if [[ "$with_explorer" == "1" ]]; then
		units+=(
			"/etc/systemd/system/${service_name}-explorer.service"
			"/etc/systemd/system/${service_name}-explorer.socket"
		)
	fi

	log "Verifying systemd unit files"
	guest sudo systemd-analyze verify "${units[@]}"

	log "Checking installed units are enabled and active"
	guest sudo systemctl is-enabled "${service_name}.service" "${service_name}.socket" "${service_name}-explorer-events.socket"
	guest sudo systemctl is-active "${service_name}.service" "${service_name}.socket" "${service_name}-explorer-events.socket"
	if [[ "$with_explorer" == "1" ]]; then
		guest sudo systemctl is-enabled "${service_name}-explorer.service" "${service_name}-explorer.socket"
		guest sudo systemctl is-active "${service_name}-explorer.service" "${service_name}-explorer.socket"
	fi
}

test_sftp_socket_activation() {
	log "Testing SFTP socket activation"
	guest sudo systemctl stop "${service_name}.service"
	guest sudo systemctl start "${service_name}.socket" "${service_name}-explorer-events.socket"
	guest sudo systemctl is-active "${service_name}.socket" "${service_name}-explorer-events.socket"
	guest env SFTP_PORT="$sftp_port" bash -s <<'EOF'
set -Eeuo pipefail
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
ssh-keygen -q -t ed25519 -N '' -f "$tmp/user"
printf 'pwd\nls\nquit\n' | sftp -q -b - -P "$SFTP_PORT" -i "$tmp/user" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null any@127.0.0.1
EOF
	guest sudo systemctl is-active "${service_name}.service"
	guest_bash "sudo journalctl --no-pager -u '${service_name}.service' | grep -F 'systemd_socket=true' >/dev/null"
}

test_explorer_socket_activation() {
	if [[ "$with_explorer" != "1" ]]; then
		return
	fi

	log "Testing explorer socket activation"
	guest sudo systemctl stop "${service_name}-explorer.service"
	guest sudo systemctl start "${service_name}-explorer.socket"
	guest sudo systemctl is-active "${service_name}-explorer.socket"
	guest env EXPLORER_PORT="$explorer_port" bash -s <<'EOF'
set -Eeuo pipefail
exec 3<>"/dev/tcp/127.0.0.1/${EXPLORER_PORT}"
printf 'GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n' >&3
IFS= read -r status <&3
[[ "$status" == HTTP/* ]]
EOF
	guest sudo systemctl is-active "${service_name}-explorer.service"
}

run_standalone_test_client() {
	if [[ "$run_test_client" != "1" ]]; then
		return
	fi

	if server_has_flag "-noauth"; then
		log "Skipping standalone test client because SERVER_EXTRA_ARGS includes -noauth"
		printf 'The full test client checks per-key ownership. With -noauth enabled, SSH accepts the none method first, so local pubkey sessions collapse into the same anonymous-by-IP identity.\n'
		return
	fi

	local guest_dir="/tmp/sftpguy-install-test"
	local install_dir="/var/lib/${service_name}"
	local client_args=(
		-host 127.0.0.1
		-port "$sftp_port"
		-threshold 1024
		-noauth=false
	)

	if server_has_flag "-admin.sftp"; then
		client_args+=(-adminkey "${install_dir}/id_ed25519")
	fi
	if [[ ${#test_client_args[@]} -gt 0 ]]; then
		client_args+=("${test_client_args[@]}")
	fi

	log "Running standalone SFTP test client"
	guest sudo "${guest_dir}/sftpguy-test-client" "${client_args[@]}"
}

main() {
	if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
		usage
		exit 0
	fi

	validate_name "LIMA_INSTANCE" "$instance"
	validate_name "SERVICE_NAME" "$service_name"
	validate_name "SERVICE_USER" "$service_user"
	validate_name "SERVICE_GROUP" "$service_group"
	validate_port "SFTP_PORT" "$sftp_port"
	validate_port "EXPLORER_PORT" "$explorer_port"
	[[ "$with_explorer" == "0" || "$with_explorer" == "1" ]] || die "WITH_EXPLORER must be 0 or 1"
	[[ "$run_test_client" == "0" || "$run_test_client" == "1" ]] || die "RUN_TEST_CLIENT must be 0 or 1"
	[[ "$keep_install" == "0" || "$keep_install" == "1" ]] || die "KEEP_INSTALL must be 0 or 1"
	[[ "$destroy_lima" == "0" || "$destroy_lima" == "1" ]] || die "DESTROY_LIMA must be 0 or 1"
	command -v limactl >/dev/null 2>&1 || die "limactl is required"
	command -v go >/dev/null 2>&1 || die "go is required to build Linux test binaries"
	if [[ -n "$server_extra_args_raw" ]]; then
		read -r -a server_extra_args <<<"$server_extra_args_raw"
	fi
	if [[ -n "$test_client_args_raw" ]]; then
		read -r -a test_client_args <<<"$test_client_args_raw"
	fi

	trap diagnose ERR
	trap cleanup EXIT

	start_lima
	cleanup_guest_install || true
	build_binaries "$(guest_goarch)"
	copy_binaries
	run_install
	verify_units
	test_sftp_socket_activation
	test_explorer_socket_activation
	run_standalone_test_client

	log "systemd -install test passed in Lima instance $instance"
}

main "$@"
