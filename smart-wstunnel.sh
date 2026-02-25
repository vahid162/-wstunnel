#!/usr/bin/env bash
set -euo pipefail

SCRIPT_VERSION="0.3.6"

DEFAULT_SERVER_LOCAL_ADDR="127.0.0.1"
DEFAULT_SERVER_LOCAL_PORT="8080"
DEFAULT_CLIENT_PING_SEC="30"
DEFAULT_NGINX_LOCATION_PATH="/"

NGINX_BIN="nginx"
NGINX_CONF_DIR="/etc/nginx/conf.d"
NGINX_RELOAD_MODE="systemd"

log() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
smart-wstunnel - bootstrap and manage wstunnel on Linux servers

Usage:
  smart-wstunnel.sh wizard
  smart-wstunnel.sh install-binary [--version <tag>]
  smart-wstunnel.sh make-server-service [options]
  smart-wstunnel.sh make-client-service [options]
  smart-wstunnel.sh print-nginx-snippet [options]

Commands:
  wizard
      True interactive setup for OUT/IN. Detects/install dependencies,
      asks step-by-step questions, and prepares services automatically.

  install-binary
      Install latest (or pinned) wstunnel binary to /usr/local/bin/wstunnel.

  make-server-service
      Create /etc/systemd/system/wstunnel-server.service (OUT server).

  make-client-service
      Create /etc/systemd/system/wstunnel-client.service (IN gateway).

  print-nginx-snippet
      Print nginx websocket reverse proxy location.

Common options:
  --yes
  --dry-run
USAGE
}

require_root() {
  [[ "${EUID}" -eq 0 ]] || die "Please run as root (sudo)."
}

confirm() {
  local prompt="${1:-Continue?}" answer
  if [[ "${ASSUME_YES:-0}" == "1" ]]; then
    return 0
  fi
  read -r -p "${prompt} [y/N]: " answer
  [[ "${answer,,}" == "y" || "${answer,,}" == "yes" ]]
}

prompt_value() {
  local prompt="$1" default="${2:-}" value=""

  if [[ "${ASSUME_YES:-0}" == "1" && -n "${default}" ]]; then
    printf '[INFO] Auto-selected default for %s: %s\n' "${prompt}" "${default}" >&2
    printf '%s' "${default}"
    return 0
  fi

  if [[ -n "${default}" ]]; then
    read -r -p "${prompt} [${default}]: " value
    printf '%s' "${value:-$default}"
  else
    read -r -p "${prompt}: " value
    printf '%s' "${value}"
  fi
}

prompt_port() {
  local prompt="$1" default="$2" val
  while true; do
    val="$(prompt_value "${prompt}" "${default}")"
    if [[ "${val}" =~ ^[0-9]+$ ]] && (( val >= 1 && val <= 65535 )); then
      printf '%s' "${val}"
      return 0
    fi
    warn "Please enter a valid port (1-65535)."
  done
}

is_valid_ipv4() {
  local ip="$1"
  [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1

  local IFS='.' octet
  read -r -a octets <<< "${ip}"
  for octet in "${octets[@]}"; do
    (( octet >= 0 && octet <= 255 )) || return 1
  done
  return 0
}

is_valid_ipv6() {
  local ip="$1"
  [[ -n "${ip}" ]] || return 1
  command -v python3 >/dev/null 2>&1 || return 1
  python3 - <<'PY' "${ip}" >/dev/null 2>&1
import ipaddress
import sys
ipaddress.IPv6Address(sys.argv[1])
PY
}

is_valid_fqdn() {
  local d="${1,,}"
  [[ -n "${d}" && ${#d} -le 253 ]] || return 1
  [[ "${d}" != .* && "${d}" != *. ]] || return 1
  [[ "${d}" != *..* ]] || return 1

  local IFS='.' label
  read -r -a labels <<< "${d}"
  [[ ${#labels[@]} -ge 2 ]] || return 1

  for label in "${labels[@]}"; do
    [[ ${#label} -ge 1 && ${#label} -le 63 ]] || return 1
    [[ "${label}" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || return 1
  done
  return 0
}

is_valid_host() {
  local host="$1"
  [[ -n "${host}" ]] || return 1
  is_valid_ipv4 "${host}" || is_valid_ipv6 "${host}" || is_valid_fqdn "${host}"
}

is_valid_host_port() {
  local value="$1" host port
  [[ -n "${value}" ]] || return 1

  if [[ "${value}" =~ ^\[(.*)\]:([0-9]{1,5})$ ]]; then
    host="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
    is_valid_ipv6 "${host}" || return 1
  elif [[ "${value}" =~ ^([^:]+):([0-9]{1,5})$ ]]; then
    host="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
    is_valid_host "${host}" || return 1
  else
    return 1
  fi

  (( port >= 1 && port <= 65535 )) || return 1
  return 0
}

is_valid_map() {
  local map="$1"
  [[ "${map}" =~ ^(tcp|udp)://(.+):([^:]+:[0-9]{1,5})(\?.*)?$ ]] || return 1

  local local_part="${BASH_REMATCH[2]}" remote_part="${BASH_REMATCH[3]}"
  is_valid_host_port "${local_part}" || return 1
  is_valid_host_port "${remote_part}" || return 1
  return 0
}

validate_domain_or_ip() {
  local value="$1"
  is_valid_host "${value}" || die "Invalid --domain value: '${value}' (expected FQDN or IP)"
}

validate_restrict_to() {
  local value="$1"
  is_valid_host_port "${value}" || die "Invalid --restrict-to value: '${value}' (expected host:port or [IPv6]:port)"
}

validate_map() {
  local value="$1"
  is_valid_map "${value}" || die "Invalid --map value: '${value}' (expected tcp://HOST:PORT:HOST:PORT or udp://... )"
}

run_cmd() {
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    log "[dry-run] $*"
    return 0
  fi
  "$@"
}

install_packages() {
  local -a pkgs=("$@")
  [[ ${#pkgs[@]} -gt 0 ]] || return 0

  if command -v apt-get >/dev/null 2>&1; then
    run_cmd apt-get update
    run_cmd apt-get install -y "${pkgs[@]}"
  elif command -v dnf >/dev/null 2>&1; then
    run_cmd dnf install -y "${pkgs[@]}"
  elif command -v yum >/dev/null 2>&1; then
    run_cmd yum install -y "${pkgs[@]}"
  elif command -v apk >/dev/null 2>&1; then
    run_cmd apk add --no-cache "${pkgs[@]}"
  else
    die "No supported package manager found (apt/dnf/yum/apk)."
  fi
}

ensure_requirements() {
  require_root

  local -a needed=(curl jq file tar unzip)
  local -a missing=()
  local b

  for b in "${needed[@]}"; do
    command -v "${b}" >/dev/null 2>&1 || missing+=("${b}")
  done

  if [[ ${#missing[@]} -eq 0 ]]; then
    log "All required dependencies are present."
    return 0
  fi

  log "Missing dependencies detected: ${missing[*]}"
  if confirm "Install missing dependencies automatically?"; then
    install_packages "${missing[@]}"
  else
    die "Cannot continue without required dependencies."
  fi
}

detect_nginx_runtime() {
  if command -v nginx >/dev/null 2>&1; then
    NGINX_BIN="$(command -v nginx)"
    NGINX_CONF_DIR="/etc/nginx/conf.d"
    NGINX_RELOAD_MODE="systemd"
    return 0
  fi

  if [[ -x "/www/server/nginx/sbin/nginx" ]]; then
    NGINX_BIN="/www/server/nginx/sbin/nginx"
    if [[ -d "/www/server/panel/vhost/nginx" ]]; then
      NGINX_CONF_DIR="/www/server/panel/vhost/nginx"
    elif [[ -d "/www/server/nginx/conf/vhost" ]]; then
      NGINX_CONF_DIR="/www/server/nginx/conf/vhost"
    else
      NGINX_CONF_DIR="/www/server/nginx/conf/conf.d"
    fi
    NGINX_RELOAD_MODE="signal"
    return 0
  fi

  return 1
}

nginx_test_and_reload() {
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    log "[dry-run] ${NGINX_BIN} -t"
    if [[ "${NGINX_RELOAD_MODE}" == "systemd" ]]; then
      log "[dry-run] systemctl reload nginx"
    else
      log "[dry-run] ${NGINX_BIN} -s reload"
    fi
    return 0
  fi

  if ! "${NGINX_BIN}" -t; then
    return 1
  fi

  if [[ "${NGINX_RELOAD_MODE}" == "systemd" ]]; then
    if ! systemctl reload nginx; then
      "${NGINX_BIN}" -s reload
    fi
  else
    "${NGINX_BIN}" -s reload
  fi
}


install_binary() {
  require_root
  local requested_version=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version) requested_version="${2:-}"; shift 2 ;;
      *) die "Unknown option for install-binary: $1" ;;
    esac
  done

  local tmp api_url release_json urls pick extracted
  tmp="$(mktemp -d)"
  trap '[[ -n "${tmp:-}" ]] && rm -rf "${tmp}"' RETURN

  if [[ -n "${requested_version}" ]]; then
    api_url="https://api.github.com/repos/erebe/wstunnel/releases/tags/${requested_version}"
  else
    api_url="https://api.github.com/repos/erebe/wstunnel/releases/latest"
  fi

  log "Fetching release metadata"
  run_cmd curl -fsSL "${api_url}" -o "${tmp}/release.json"
  release_json="${tmp}/release.json"

  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    log "[dry-run] skipping asset detection"
    log "[dry-run] install -m 0755 <downloaded-wstunnel> /usr/local/bin/wstunnel"
    return 0
  fi

  urls="$(jq -r '.assets[].browser_download_url' "${release_json}")"
  pick="$(printf '%s\n' "${urls}" | grep -Ei 'linux.*(x86_64|amd64)|((x86_64|amd64).*(linux))' | head -n1 || true)"
  [[ -n "${pick}" ]] || die "Could not auto-pick Linux amd64 asset"

  log "Selected asset: ${pick}"
  curl -fL "${pick}" -o "${tmp}/asset"

  if file "${tmp}/asset" | grep -qi 'gzip compressed'; then
    mv "${tmp}/asset" "${tmp}/asset.tar.gz"
    tar -xzf "${tmp}/asset.tar.gz" -C "${tmp}"
  elif file "${tmp}/asset" | grep -qi 'Zip archive'; then
    mv "${tmp}/asset" "${tmp}/asset.zip"
    unzip -q "${tmp}/asset.zip" -d "${tmp}"
  else
    chmod +x "${tmp}/asset"
  fi

  extracted="$(find "${tmp}" -type f -name wstunnel -perm -111 2>/dev/null | head -n1 || true)"
  [[ -n "${extracted}" ]] || extracted="${tmp}/asset"

  install -m 0755 "${extracted}" /usr/local/bin/wstunnel
  /usr/local/bin/wstunnel --help >/dev/null
  log "wstunnel installed"
}

ensure_nginx_installed() {
  if detect_nginx_runtime; then
    log "nginx detected: ${NGINX_BIN} (conf dir: ${NGINX_CONF_DIR})"
    return 0
  fi

  warn "nginx is not installed on this server."
  if ! confirm "Install nginx now?"; then
    warn "Skipping nginx install. You must install/configure reverse proxy manually."
    return 1
  fi

  install_packages nginx
  run_cmd systemctl enable --now nginx

  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    NGINX_BIN="nginx"
    NGINX_CONF_DIR="/etc/nginx/conf.d"
    NGINX_RELOAD_MODE="systemd"
    log "[dry-run] assuming nginx available after install"
    return 0
  fi

  if ! detect_nginx_runtime; then
    die "nginx install finished but binary was not detected."
  fi

  log "nginx installed: ${NGINX_BIN}"
  return 0
}

build_nginx_snippet() {
  local location_path="$1" upstream="$2"
  cat <<EOF_SNIPPET
location ${location_path} {
  proxy_pass ${upstream};
  proxy_http_version 1.1;
  proxy_set_header Upgrade \$http_upgrade;
  proxy_set_header Connection "upgrade";
  proxy_set_header Host \$host;
  proxy_read_timeout 1d;
}
EOF_SNIPPET
}

print_nginx_snippet() {
  local location_path='/' upstream='http://127.0.0.1:8080'
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --location-path) location_path="${2:-}"; shift 2 ;;
      --upstream) upstream="${2:-}"; shift 2 ;;
      *) die "Unknown option for print-nginx-snippet: $1" ;;
    esac
  done
  build_nginx_snippet "${location_path}" "${upstream}"
}

restore_nginx_conf() {
  local conf_path="$1" backup_path="${2:-}"

  if [[ -n "${backup_path}" && -f "${backup_path}" ]]; then
    cp "${backup_path}" "${conf_path}"
    warn "Rolled back nginx config to backup: ${backup_path}"
  else
    rm -f "${conf_path}"
    warn "Rolled back nginx config by removing new file: ${conf_path}"
  fi
}

configure_nginx_ws() {
  local domain="$1" location_path="$2" upstream="$3"

  local conf_path="${NGINX_CONF_DIR}/wstunnel-${domain}.conf"
  local snippet
  snippet="$(build_nginx_snippet "${location_path}" "${upstream}")"

  local content
  read -r -d '' content <<EOF_CONF || true
server {
  listen 443 ssl;
  listen [::]:443 ssl;
  server_name ${domain};

  # IMPORTANT: replace with your certificate paths before reload.
  ssl_certificate /etc/letsencrypt/live/${domain}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;

${snippet}
}
EOF_CONF

  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    log "[dry-run] would write ${conf_path}:"
    printf '%s\n' "${content}"
    nginx_test_and_reload
    return 0
  fi

  mkdir -p "${NGINX_CONF_DIR}"

  local backup_path=""
  if [[ -f "${conf_path}" ]]; then
    backup_path="${conf_path}.bak.$(date +%Y%m%d-%H%M%S)"
    cp "${conf_path}" "${backup_path}"
    log "nginx backup created: ${backup_path}"
  fi

  printf '%s\n' "${content}" > "${conf_path}"

  if ! nginx_test_and_reload; then
    warn "nginx test/reload failed after writing ${conf_path}. Rolling back config."
    restore_nginx_conf "${conf_path}" "${backup_path}"
    nginx_test_and_reload || true
    die "nginx config apply failed and rollback was attempted"
  fi

  log "nginx config applied: ${conf_path}"
}


append_tunnel_profile() {
  local mode="$1"
  local -n out_ref="$2"

  printf '\nChoose tunnel profile:\n'
  printf '  1) Custom\n'
  printf '  2) Xray/V2Ray (TCP)\n'
  printf '  3) OpenVPN (TCP)\n'
  printf '  4) WireGuard (UDP + timeout_sec=0)\n'
  printf '  5) Cisco AnyConnect (TLS/TCP)\n'

  local profile p
  profile="$(prompt_value "Enter choice" "1")"

  case "${profile}" in
    2) p="$(prompt_port "Port" "10000")" ;;
    3) p="$(prompt_port "Port" "22335")" ;;
    4) p="$(prompt_port "Port" "51820")" ;;
    5) p="$(prompt_port "Port" "4443")" ;;
    1)
      if [[ "${mode}" == "server" ]]; then
        p="$(prompt_value "Enter destination host:port" "127.0.0.1:22335")"
        validate_restrict_to "${p}"
        out_ref+=("${p}")
      else
        p="$(prompt_value "Enter full map" "tcp://0.0.0.0:22335:127.0.0.1:22335")"
        validate_map "${p}"
        out_ref+=("${p}")
      fi
      return 0
      ;;
    *)
      warn "Invalid choice."
      append_tunnel_profile "${mode}" out_ref
      return 0
      ;;
  esac

  if [[ "${mode}" == "server" ]]; then
    out_ref+=("127.0.0.1:${p}")
  elif [[ "${profile}" == "4" ]]; then
    out_ref+=("udp://0.0.0.0:${p}:127.0.0.1:${p}?timeout_sec=0")
  else
    out_ref+=("tcp://0.0.0.0:${p}:127.0.0.1:${p}")
  fi
}

make_server_service() {
  require_root
  local secret="" listen_addr="${DEFAULT_SERVER_LOCAL_ADDR}" listen_port="${DEFAULT_SERVER_LOCAL_PORT}"
  local -a restrict_to=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --secret) secret="${2:-}"; shift 2 ;;
      --listen-addr) listen_addr="${2:-}"; shift 2 ;;
      --listen-port) listen_port="${2:-}"; shift 2 ;;
      --restrict-to) restrict_to+=("${2:-}"); shift 2 ;;
      *) die "Unknown option for make-server-service: $1" ;;
    esac
  done

  [[ -n "${secret}" ]] || die "--secret is required"
  is_valid_host "${listen_addr}" || die "Invalid --listen-addr value: '${listen_addr}'"
  [[ "${listen_port}" =~ ^[0-9]+$ ]] && (( listen_port >= 1 && listen_port <= 65535 )) || die "Invalid --listen-port value: '${listen_port}'"
  [[ ${#restrict_to[@]} -gt 0 ]] || die "At least one --restrict-to is required"

  local rt
  for rt in "${restrict_to[@]}"; do
    validate_restrict_to "${rt}"
  done

  local service_file="/etc/systemd/system/wstunnel-server.service"
  {
    echo "[Unit]"
    echo "Description=wstunnel server (behind nginx, ws on localhost)"
    echo "After=network-online.target"
    echo "Wants=network-online.target"
    echo
    echo "[Service]"
    printf 'ExecStart=/usr/local/bin/wstunnel server ws://%s:%s \\\n' "${listen_addr}" "${listen_port}"
    printf '  --restrict-http-upgrade-path-prefix %q \\\n' "${secret}"
    local i
    for i in "${!restrict_to[@]}"; do
      if [[ "$i" -eq $((${#restrict_to[@]} - 1)) ]]; then
        printf '  --restrict-to %q\n' "${restrict_to[$i]}"
      else
        printf '  --restrict-to %q \\\n' "${restrict_to[$i]}"
      fi
    done
    echo "Restart=always"
    echo "RestartSec=2"
    echo
    echo "[Install]"
    echo "WantedBy=multi-user.target"
  } > /tmp/wstunnel-server.service.rendered

  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    log "[dry-run] would write ${service_file}:"
    cat /tmp/wstunnel-server.service.rendered
    return 0
  fi

  cp /tmp/wstunnel-server.service.rendered "${service_file}"
  systemctl daemon-reload
  systemctl enable --now wstunnel-server.service
  systemctl --no-pager --full status wstunnel-server.service || true
  log "Server service created"
}

make_client_service() {
  require_root
  local domain="" secret="" ping_sec="${DEFAULT_CLIENT_PING_SEC}"
  local -a maps=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --domain) domain="${2:-}"; shift 2 ;;
      --secret) secret="${2:-}"; shift 2 ;;
      --ping-sec) ping_sec="${2:-}"; shift 2 ;;
      --map) maps+=("${2:-}"); shift 2 ;;
      *) die "Unknown option for make-client-service: $1" ;;
    esac
  done

  [[ -n "${domain}" ]] || die "--domain is required"
  [[ -n "${secret}" ]] || die "--secret is required"
  validate_domain_or_ip "${domain}"
  [[ "${ping_sec}" =~ ^[0-9]+$ ]] || die "Ping interval must be numeric"
  [[ ${#maps[@]} -gt 0 ]] || die "At least one --map is required"

  local mp
  for mp in "${maps[@]}"; do
    validate_map "${mp}"
  done

  local service_file="/etc/systemd/system/wstunnel-client.service"
  {
    echo "[Unit]"
    echo "Description=wstunnel client (IN -> OUT over WSS:443)"
    echo "After=network-online.target"
    echo "Wants=network-online.target"
    echo
    echo "[Service]"
    printf 'ExecStart=/usr/local/bin/wstunnel client \\\n'
    printf '  --http-upgrade-path-prefix %q \\\n' "${secret}"
    printf '  --websocket-ping-frequency-sec %q \\\n' "${ping_sec}"
    local i
    for i in "${!maps[@]}"; do
      printf "  -L '%s' \\\\" "${maps[$i]}"
      echo
    done
    printf '  wss://%s:443\n' "${domain}"
    echo "Restart=always"
    echo "RestartSec=2"
    echo
    echo "[Install]"
    echo "WantedBy=multi-user.target"
  } > /tmp/wstunnel-client.service.rendered

  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    log "[dry-run] would write ${service_file}:"
    cat /tmp/wstunnel-client.service.rendered
    return 0
  fi

  cp /tmp/wstunnel-client.service.rendered "${service_file}"
  systemctl daemon-reload
  systemctl enable --now wstunnel-client.service
  systemctl --no-pager --full status wstunnel-client.service || true
  log "Client service created"
}

print_out_summary() {
  local service_name="wstunnel-server.service"
  local service_file="/etc/systemd/system/wstunnel-server.service"
  local nginx_conf_path="${1:-}"

  printf '
=== OUT Post-install checklist ===
'
  printf 'Service: %s
' "${service_name}"
  printf 'Service file: %s
' "${service_file}"
  if [[ -n "${nginx_conf_path}" ]]; then
    printf 'Nginx config: %s
' "${nginx_conf_path}"
  else
    printf 'Nginx config: (not auto-generated in this run)
'
  fi

  printf '
Health checks (copy/paste):
'
  printf 'sudo systemctl status %s --no-pager -l
' "${service_name}"
  printf 'sudo journalctl -u %s -n 200 --no-pager
' "${service_name}"
  printf "sudo ss -lntup | egrep '(:443|:8080|:22335|:24443|:51820)' || true
"
  if [[ -n "${nginx_conf_path}" ]]; then
    printf 'sudo %s -t
' "${NGINX_BIN}"
  fi
  printf '=== End checklist ===

'
}

print_in_summary() {
  local service_name="wstunnel-client.service"
  local service_file="/etc/systemd/system/wstunnel-client.service"

  printf '
=== IN Post-install checklist ===
'
  printf 'Service: %s
' "${service_name}"
  printf 'Service file: %s
' "${service_file}"

  printf '
Health checks (copy/paste):
'
  printf 'sudo systemctl status %s --no-pager -l
' "${service_name}"
  printf 'sudo journalctl -u %s -n 200 --no-pager
' "${service_name}"
  printf "sudo ss -lntup | egrep '(:443|:8080|:22335|:24443|:51820)' || true
"
  printf '=== End checklist ===

'
}

wizard_out() {
  local secret listen_addr listen_port domain location_path nginx_conf_path=""
  local -a restricts=()

  secret="$(prompt_value "Enter shared secret" "gw-2026-01")"
  listen_addr="$(prompt_value "wstunnel listen address" "${DEFAULT_SERVER_LOCAL_ADDR}")"
  listen_port="$(prompt_port "wstunnel listen port" "${DEFAULT_SERVER_LOCAL_PORT}")"

  while true; do
    append_tunnel_profile "server" restricts
    if [[ "${ASSUME_YES:-0}" == "1" ]]; then
      break
    fi
    if ! confirm "Add another allowed destination?"; then
      break
    fi
  done

  local -a args=(--secret "${secret}" --listen-addr "${listen_addr}" --listen-port "${listen_port}")
  local r
  for r in "${restricts[@]}"; do
    args+=(--restrict-to "${r}")
  done
  make_server_service "${args[@]}"

  if ensure_nginx_installed; then
    domain="$(prompt_value "Enter OUT domain for nginx server_name" "tnl.example.com")"
    validate_domain_or_ip "${domain}"
    location_path="$(prompt_value "nginx location path" "${DEFAULT_NGINX_LOCATION_PATH}")"

    if confirm "Auto-generate nginx config and reload nginx now?"; then
      configure_nginx_ws "${domain}" "${location_path}" "http://${listen_addr}:${listen_port}"
      nginx_conf_path="${NGINX_CONF_DIR}/wstunnel-${domain}.conf"
    else
      printf '\n=== nginx snippet ===\n'
      build_nginx_snippet "${location_path}" "http://${listen_addr}:${listen_port}"
      printf '=== end ===\n'
    fi
  fi

  print_out_summary "${nginx_conf_path}"
  log "OUT setup finished."
}

wizard_in() {
  local domain secret ping_sec
  local -a maps=()

  domain="$(prompt_value "Enter OUT domain (TLS on 443)" "tnl.example.com")"
  validate_domain_or_ip "${domain}"
  secret="$(prompt_value "Enter shared secret (must match OUT)" "gw-2026-01")"
  ping_sec="$(prompt_value "WebSocket ping interval (sec)" "${DEFAULT_CLIENT_PING_SEC}")"
  [[ "${ping_sec}" =~ ^[0-9]+$ ]] || die "Ping interval must be numeric"

  while true; do
    append_tunnel_profile "client" maps
    if [[ "${ASSUME_YES:-0}" == "1" ]]; then
      break
    fi
    if ! confirm "Add another map?"; then
      break
    fi
  done

  local -a args=(--domain "${domain}" --secret "${secret}" --ping-sec "${ping_sec}")
  local m
  for m in "${maps[@]}"; do
    args+=(--map "${m}")
  done
  make_client_service "${args[@]}"
  print_in_summary
  log "IN setup finished."
}

wizard() {
  require_root
  log "Welcome to smart-wstunnel true wizard"

  ensure_requirements

  if confirm "Install/upgrade wstunnel binary now?"; then
    install_binary
  else
    warn "Skipping wstunnel binary installation"
  fi

  printf '\nSelect server role:\n'
  printf '  1) OUT server\n'
  printf '  2) IN gateway\n'

  local role
  role="$(prompt_value "Enter choice" "1")"

  case "${role}" in
    1) wizard_out ;;
    2) wizard_in ;;
    *) die "Invalid choice" ;;
  esac

  log "Wizard completed."
}

main() {
  [[ $# -ge 1 ]] || { usage; exit 1; }

  ASSUME_YES=0
  DRY_RUN=0

  local cmd="$1"
  shift

  local -a filtered=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --yes) ASSUME_YES=1; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      *) filtered+=("$1"); shift ;;
    esac
  done
  set -- "${filtered[@]}"

  case "${cmd}" in
    wizard) wizard ;;
    install-binary) install_binary "$@" ;;
    make-server-service) make_server_service "$@" ;;
    make-client-service) make_client_service "$@" ;;
    print-nginx-snippet) print_nginx_snippet "$@" ;;
    -h|--help|help) usage ;;
    version|--version) echo "smart-wstunnel ${SCRIPT_VERSION}" ;;
    *) die "Unknown command: ${cmd}" ;;
  esac
}

main "$@"
