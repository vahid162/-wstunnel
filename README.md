# Smart WSTunnel Bootstrap

این ریپو یک ابزار **خلاصه و عملی** برای راه‌اندازی `wstunnel` بین سرور ایران (IN) و خارج (OUT) است.
هدف: با یک اسکریپت، نصب + ساخت سرویس systemd + الگوی nginx را سریع انجام بدهی.

> این README عمدی کوتاه است؛ دستورات اجرایی داخل اسکریپت به انگلیسی هستند.

## چه چیزی داخل ریپو است؟

- `smart-wstunnel.sh`: اسکریپت اصلی برای نصب و تولید سرویس‌ها.
- `VERSION`: نسخه فعلی ابزار.
- `CHANGELOG.md`: تاریخچه تغییرات نسخه.

## سناریوی پیشنهادی

- روی **OUT**: nginx روی 443 (TLS واقعی) + wstunnel روی `127.0.0.1:8080`
- روی **IN**: wstunnel client که چند `-L` برای TCP/UDP باز می‌کند

## شروع سریع

### 1) OUT (سرور خارج)

```bash
sudo bash smart-wstunnel.sh install-binary

sudo bash smart-wstunnel.sh make-server-service \
  --secret gw-2026-01 \
  --restrict-to 127.0.0.1:22335 \
  --restrict-to 127.0.0.1:24443

sudo bash smart-wstunnel.sh print-nginx-snippet --location-path / --upstream http://127.0.0.1:8080
```

اسنیپت nginx خروجی را داخل vhost دامنه‌ات روی 443 قرار بده و `nginx -t && systemctl reload nginx` بزن.

### 2) IN (سرور ایران)

```bash
sudo bash smart-wstunnel.sh install-binary

sudo bash smart-wstunnel.sh make-client-service \
  --domain tnl.example.com \
  --secret gw-2026-01 \
  --map tcp://0.0.0.0:22335:127.0.0.1:22335 \
  --map tcp://0.0.0.0:24443:127.0.0.1:24443 \
  --map udp://0.0.0.0:51820:127.0.0.1:51820?timeout_sec=0
```

## نکات حرفه‌ای مهم

- همیشه روی OUT از `--restrict-to` فقط برای پورت‌های لازم استفاده کن.
- `--secret` روی client/server باید یکی باشد.
- برای UDP VPN (مثل WireGuard) بهتر است `timeout_sec=0` تنظیم شود.
- اگر اتصال‌های طولانی قطع می‌شوند، ping (`--websocket-ping-frequency-sec`) را کم‌کم تنظیم کن.

## عیب‌یابی سریع

```bash
sudo systemctl status wstunnel-server --no-pager -l
sudo systemctl status wstunnel-client --no-pager -l
sudo journalctl -u wstunnel-server -n 200 --no-pager
sudo journalctl -u wstunnel-client -n 200 --no-pager
sudo ss -lntup | egrep '(:443|:8080|:22335|:24443|:51820)\b' || true
```

## پشتیبانی سرویس‌ها

این روش برای TCP/UDP مناسب است و برای موارد رایج زیر جواب می‌دهد:
- Xray/V2Ray (TCP)
- OpenVPN (TCP یا UDP)
- Cisco AnyConnect در حالت TLS-only
- WireGuard (UDP)

## نسخه

نسخه فعلی: `0.1.0` (فایل `VERSION`)
