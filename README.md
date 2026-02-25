# Smart WSTunnel Bootstrap

این پروژه برای **نصب و راه‌اندازی هوشمند wstunnel** ساخته شده تا با یک دستور، سرور IN یا OUT را مرحله‌به‌مرحله آماده کنی.

## اجرای یک‌خطی (مبتدی‌پسند)

روی هر سرور (ایران یا خارج) این دستور را بزن:

```bash
sudo bash smart-wstunnel.sh wizard
```

Wizard ازت سوال می‌پرسد و خودش جلو می‌رود:
- نصب پیش‌نیازها (`curl`, `jq`, `unzip`, ...)
- نصب/آپدیت باینری `wstunnel`
- انتخاب نقش سرور: OUT یا IN
- گرفتن تنظیمات سرویس‌ها (secret, domain, ports, maps)
- ساخت و فعال‌سازی سرویس systemd

## نقش‌ها

- **OUT**: `wstunnel server` پشت nginx (روی localhost)
- **IN**: `wstunnel client` برای map کردن پورت‌های TCP/UDP

## حالت حرفه‌ای (بدون Wizard)

### نصب باینری

```bash
sudo bash smart-wstunnel.sh install-binary
```

### ساخت سرویس OUT

```bash
sudo bash smart-wstunnel.sh make-server-service \
  --secret gw-2026-01 \
  --restrict-to 127.0.0.1:22335 \
  --restrict-to 127.0.0.1:24443
```

### ساخت سرویس IN

```bash
sudo bash smart-wstunnel.sh make-client-service \
  --domain tnl.example.com \
  --secret gw-2026-01 \
  --map tcp://0.0.0.0:22335:127.0.0.1:22335 \
  --map udp://0.0.0.0:51820:127.0.0.1:51820?timeout_sec=0
```

### ساخت snippet برای nginx

```bash
sudo bash smart-wstunnel.sh print-nginx-snippet --location-path / --upstream http://127.0.0.1:8080
```

## عیب‌یابی سریع

```bash
sudo systemctl status wstunnel-server --no-pager -l
sudo systemctl status wstunnel-client --no-pager -l
sudo journalctl -u wstunnel-server -n 200 --no-pager
sudo journalctl -u wstunnel-client -n 200 --no-pager
sudo ss -lntup | egrep '(:443|:8080|:22335|:24443|:51820)\b' || true
```

## نسخه

نسخه فعلی: `0.2.0`
