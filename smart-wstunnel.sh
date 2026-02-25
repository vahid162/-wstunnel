#!/usr/bin/env bash
set -euo pipefail

SCRIPT_VERSION="0.2.0"

DEFAULT_SERVER_LOCAL_ADDR="127.0.0.1"
DEFAULT_SERVER_LOCAL_PORT="8080"
DEFAULT_CLIENT_PING_SEC="30"

log() {
  printf '[INFO] %s\n' "$*"
}

warn() {
  printf '[WARN] %s\n' "$*" >&2
}

die() {
  printf '[ERROR] %s\n' "$*" >&2
  exit 1
}

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
      Beginner-friendly interactive setup.
      Asks questions step-by-step and prepares OUT or IN server.

  install-binary
      Install latest (or pinned) wstunnel binary to /usr/local/bin/wstunnel.

  make-server-service
      Create /etc/systemd/system/wstunnel-server.service (OUT server).
      Intended for running behind nginx reverse proxy on localhost.

  make-client-service
      Create /etc/systemd/system/wstunnel-client.service (IN gateway).
      Maps one or more local listeners to remote destinations through WSS.

  print-nginx-snippet
      Print a ready-to-use nginx location block for websocket upgrade.

Common options:
  --yes                         Non-interactive mode, skip confirmations.
  --dry-run                     Print files/commands instead of applying.

Server service options:
  --secret <value>              Required. Upgrade path secret.
  --listen-addr <ip>            Default: 127.0.0.1
  --listen-port <port>          Default: 8080
  --restrict-to <host:port>     Required. Repeat for each allowed destination.

Client service options:
  --domain <fqdn>               Required. OUT domain served by nginx TLS.
  --secret <value>              Required. Must match server secret.
  --map <spec>                  Required. Repeat for each tunnel map.
                                Examples:
                                  tcp://0.0.0.0:22335:127.0.0.1:22335
                                  udp://0.0.0.0:51820:127.0.0.1:51820?timeout_sec=0
  --ping-sec <seconds>          Default: 30

Examples:
  sudo ./smart-wstunnel.sh wizard
  sudo ./smart-wstunnel.sh install-binary --version v10.1.8
USAGE
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Please run as root (use sudo)."
  fi
}

confirm() {
  local prompt="${1:-Continue?}"
  if [[ "${ASSUME_YES:-0}" == "1" ]]; then
    return 0
  fi
  local answer
  read -r -p "${prompt} [y/N]: " answer
  [[ "${answer,,}" == "y" || "${answer,,}" == "yes" ]]
}

prompt_value() {
  local prompt="$1"
  local default="${2:-}"
  local value=""

  if [[ -n "${default}" ]]; then
    read -r -p "${prompt} [${default}]: " value
    printf '%s' "${value:-$default}"
  else
    read -r -p "${prompt}: " value
    printf '%s' "${value}"
  fi
}

prompt_port() {
  local prompt="$1"
  local default="$2"
  local val
  while true; do
    val="$(prompt_value "${prompt}" "${default}")"
    if [[ "${val}" =~ ^[0-9]+$ ]] && (( val >= 1 && val <= 65535 )); then
      printf '%s' "${val}"
      return 0
    fi
    warn "Please enter a valid port (1-65535)."
  done
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

  local profile
  profile="$(prompt_value "Enter choice" "1")"

  case "${profile}" in
    2)
      local p
      p="$(prompt_port "Port" "10000")"
      if [[ "${mode}" == "server" ]]; then
        out_ref+=("127.0.0.1:${p}")
      else
        out_ref+=("tcp://0.0.0.0:${p}:127.0.0.1:${p}")
      fi
      ;;
    3)
      local p
      p="$(prompt_port "Port" "22335")"
      if [[ "${mode}" == "server" ]]; then
        out_ref+=("127.0.0.1:${p}")
      else
        out_ref+=("tcp://0.0.0.0:${p}:127.0.0.1:${p}")
      fi
      ;;
    4)
      local p
      p="$(prompt_port "Port" "51820")"
      if [[ "${mode}" == "server" ]]; then
        out_ref+=("127.0.0.1:${p}")
      else
        out_ref+=("udp://0.0.0.0:${p}:127.0.0.1:${p}?timeout_sec=0")
      fi
      ;;
    5)
      local p
      p="$(prompt_port "Port" "4443")"
      if [[ "${mode}" == "server" ]]; then
        out_ref+=("127.0.0.1:${p}")
      else
        out_ref+=("tcp://0.0.0.0:${p}:127.0.0.1:${p}")
      fi
      ;;
    1)
      if [[ "${mode}" == "server" ]]; then
        local r
        r="$(prompt_value "Enter destination host:port (example 127.0.0.1:22335)")"
        [[ -n "${r}" ]] || die "Value cannot be empty"
        out_ref+=("${r}")
      else
        local m
        m="$(prompt_value "Enter full map (example tcp://0.0.0.0:22335:127.0.0.1:22335)")"
        [[ -n "${m}" ]] || die "Value cannot be empty"
        out_ref+=("${m}")
      fi
      ;;
    *)
      warn "Invalid choice. Using Custom mode."
      append_tunnel_profile "${mode}" out_ref
      ;;
  esac
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

  local tmp release_json api_url urls pick extracted
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' RETURN

  if [[ -n "${requested_version}" ]]; then
    api_url="https://api.github.com/repos/erebe/wstunnel/releases/tags/${requested_version}"
  else
    api_url="https://api.github.com/repos/erebe/wstunnel/releases/latest"
  fi

  log "Fetching release metadata from GitHub"
  curl -fsSL "${api_url}" -o "${tmp}/release.json"
  release_json="${tmp}/release.json"

  urls="$(jq -r '.assets[].browser_download_url' "${release_json}")"
  pick="$(printf '%s\n' "${urls}" | grep -Ei 'linux.*(x86_64|amd64)|((x86_64|amd64).*(linux))' | head -n1 || true)"

  [[ -n "${pick}" ]] || die "Could not auto-pick Linux amd64 asset."
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
  if [[ -z "${extracted}" ]]; then
    extracted="${tmp}/asset"
  fi

  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    log "[dry-run] install -m 0755 ${extracted} /usr/local/bin/wstunnel"
    return 0
  fi

  install -m 0755 "${extracted}" /usr/local/bin/wstunnel
  /usr/local/bin/wstunnel --help >/dev/null
  log "wstunnel installed successfully"
}

ensure_requirements() {
  require_root
  local -a needed=(curl jq file tar unzip systemctl)
  local -a missing=()
  local b
  for b in "${needed[@]}"; do
    if ! command -v "${b}" >/dev/null 2>&1; then
      missing+=("${b}")
    fi
  done

  if [[ ${#missing[@]} -eq 0 ]]; then
    return 0
  fi

  log "Installing missing packages: ${missing[*]}"
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    log "[dry-run] apt-get update && apt-get install -y curl jq file tar unzip systemd"
    return 0
  fi

  apt-get update
  apt-get install -y curl jq file tar unzip systemd
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
  log "Server service created: ${service_file}"
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
      printf "  -L '%s' \\" "${maps[$i]}"
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
  log "Client service created: ${service_file}"
}

print_nginx_snippet() {
  local location_path='/'
  local upstream='http://127.0.0.1:8080'

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --location-path) location_path="${2:-}"; shift 2 ;;
      --upstream) upstream="${2:-}"; shift 2 ;;
      *) die "Unknown option for print-nginx-snippet: $1" ;;
    esac
  done

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

wizard() {
  require_root

  log "Welcome to smart-wstunnel wizard"
  log "This wizard will ask simple questions and configure one server."

  ensure_requirements

  if confirm "Install/upgrade wstunnel binary now?"; then
    install_binary
  else
    warn "Skipping binary installation"
  fi

  local role
  printf '\nSelect server role:\n'
  printf '  1) OUT server (wstunnel server behind nginx)\n'
  printf '  2) IN gateway (wstunnel client)\n'
  role="$(prompt_value "Enter choice" "1")"

  case "${role}" in
    1)
      local secret listen_addr listen_port
      local -a restricts=()

      secret="$(prompt_value "Enter shared secret for path prefix" "gw-2026-01")"
      listen_addr="$(prompt_value "wstunnel listen address" "${DEFAULT_SERVER_LOCAL_ADDR}")"
      listen_port="$(prompt_port "wstunnel listen port" "${DEFAULT_SERVER_LOCAL_PORT}")"

      while true; do
        append_tunnel_profile "server" restricts
        if ! confirm "Add another allowed destination (restrict-to)?"; then
          break
        fi
      done

      local -a args=(--secret "${secret}" --listen-addr "${listen_addr}" --listen-port "${listen_port}")
      local r
      for r in "${restricts[@]}"; do
        args+=(--restrict-to "${r}")
      done
      make_server_service "${args[@]}"

      printf '\n=== nginx snippet (copy into your TLS vhost on OUT) ===\n'
      print_nginx_snippet --location-path / --upstream "http://${listen_addr}:${listen_port}"
      printf '=== end ===\n\n'
      log "Done. Next step: apply nginx config, then reload nginx."
      ;;
    2)
      local domain secret ping_sec
      local -a maps=()

      domain="$(prompt_value "Enter OUT domain (TLS on 443)" "tnl.example.com")"
      secret="$(prompt_value "Enter shared secret (must match OUT)" "gw-2026-01")"
      ping_sec="$(prompt_value "WebSocket ping interval (sec)" "${DEFAULT_CLIENT_PING_SEC}")"
      [[ "${ping_sec}" =~ ^[0-9]+$ ]] || die "Ping interval must be numeric"

      while true; do
        append_tunnel_profile "client" maps
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
      log "Done. IN gateway is ready."
      ;;
    *)
      die "Invalid choice"
      ;;
  esac
}

main() {
  [[ $# -ge 1 ]] || { usage; exit 1; }

  local cmd="$1"
  shift

  ASSUME_YES=0
  DRY_RUN=0

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
    wizard)
      wizard
      ;;
    install-binary)
      install_binary "$@"
      ;;
    make-server-service)
      make_server_service "$@"
      ;;
    make-client-service)
      make_client_service "$@"
      ;;
    print-nginx-snippet)
      print_nginx_snippet "$@"
      ;;
    -h|--help|help)
      usage
      ;;
    version|--version)
      echo "smart-wstunnel ${SCRIPT_VERSION}"
      ;;
    *)
      die "Unknown command: ${cmd}"
      ;;
  esac
}

main "$@"
