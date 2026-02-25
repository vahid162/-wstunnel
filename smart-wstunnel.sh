#!/usr/bin/env bash
set -euo pipefail

SCRIPT_VERSION="0.3.3"

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

  "${NGINX_BIN}" -t
  if [[ "${NGINX_RELOAD_MODE}" == "systemd" ]]; then
    systemctl reload nginx || "${NGINX_BIN}" -s reload
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
  printf '%s\n' "${content}" > "${conf_path}"
  nginx_test_and_reload
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
        out_ref+=("${p}")
      else
        p="$(prompt_value "Enter full map" "tcp://0.0.0.0:22335:127.0.0.1:22335")"
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
  [[ ${#restrict_to[@]} -gt 0 ]] || die "At least one --restrict-to is required"

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
  [[ ${#maps[@]} -gt 0 ]] || die "At least one --map is required"

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

wizard_out() {
  local secret listen_addr listen_port domain location_path
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
    location_path="$(prompt_value "nginx location path" "${DEFAULT_NGINX_LOCATION_PATH}")"

    if confirm "Auto-generate nginx config and reload nginx now?"; then
      configure_nginx_ws "${domain}" "${location_path}" "http://${listen_addr}:${listen_port}"
    else
      printf '\n=== nginx snippet ===\n'
      build_nginx_snippet "${location_path}" "http://${listen_addr}:${listen_port}"
      printf '=== end ===\n'
    fi
  fi

  log "OUT setup finished."
}

wizard_in() {
  local domain secret ping_sec
  local -a maps=()

  domain="$(prompt_value "Enter OUT domain (TLS on 443)" "tnl.example.com")"
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
