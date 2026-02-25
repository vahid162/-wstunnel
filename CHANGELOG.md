# Changelog

## 0.3.5
- Added nginx config backup (timestamped) before overwrite in auto-config flow.
- Added automatic rollback if nginx config test/reload fails after applying new config.

## 0.3.4
- Added stricter input validation for domain/FQDN/IP values in wizard and CLI flags.
- Added strict format validation for `--map` and `--restrict-to` to reduce beginner configuration errors.

## 0.3.3
- Updated README auto-installer command to use the repository real GitHub raw URL.
- Revalidated wizard/script smoke flows after docs update.

## 0.3.2
- Added nginx runtime detection for both system installs and aaPanel installs with custom binary/conf paths.
- Updated nginx config/reload flow to use detected binary/path safely.

## 0.3.1
- Fixed wizard `--yes` behavior to avoid infinite add-more loops and auto-select defaults safely.

## 0.3.0
- Upgraded wizard to true end-to-end interactive installer with OUT/IN flows.
- Added nginx detection and optional auto-install/config/reload on OUT.
- Added package-manager aware dependency installation (apt/dnf/yum/apk).

## 0.2.0
- Added interactive `wizard` mode for one-command, beginner-friendly setup.
- Added automatic dependency installation for required tools.
- Updated README with one-line quickstart flow.

## 0.1.0
- Added `smart-wstunnel.sh` to install wstunnel and generate server/client systemd units.
- Replaced README with a concise Persian guide for IN/OUT deployment.
