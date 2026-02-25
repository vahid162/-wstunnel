# Smart WSTunnel Bootstrap

این پروژه یک **ویزارد واقعی** برای `wstunnel` است تا با یک دستور، نصب و پیکربندی روی OUT/IN را انجام بدهی.

## اجرای یک‌خطی (مثل ریپوهای auto-installer)

بعد از اینکه فایل اسکریپت روی GitHub قرار گرفت، می‌توانی مستقیم این دستور را بزنی:

```bash
bash <(curl -fsSL "https://raw.githubusercontent.com/<YOUR_USER>/<YOUR_REPO>/main/smart-wstunnel.sh") wizard
```

یا داخل همین ریپو:

```bash
sudo bash smart-wstunnel.sh wizard
```

## این Wizard چه چیزهایی را خودکار می‌کند؟

- بررسی و نصب dependencyهای لازم (`curl`, `jq`, `unzip`, ...)
- نصب/آپدیت باینری رسمی `wstunnel`
- انتخاب نقش سرور (OUT یا IN)
- ساخت سرویس systemd برای `wstunnel-server` یا `wstunnel-client`
- روی OUT: تشخیص نصب بودن nginx و در صورت نیاز نصب خودکار
- روی OUT: امکان ساخت خودکار کانفیگ nginx و `nginx -t` + reload
- روی IN: ساخت mapهای TCP/UDP با پروفایل آماده (Xray/OpenVPN/WireGuard/AnyConnect)

## نکته مهم (جواب سوال رایج)

- **nginx معمولاً فقط روی OUT لازم است** (برای WSS روی 443).
- روی **IN** معمولاً nginx لازم نیست؛ فقط `wstunnel client` کافی است.

## دستورات حرفه‌ای (بدون Wizard)

```bash
sudo bash smart-wstunnel.sh install-binary
sudo bash smart-wstunnel.sh make-server-service --secret gw-2026-01 --restrict-to 127.0.0.1:22335
sudo bash smart-wstunnel.sh make-client-service --domain tnl.example.com --secret gw-2026-01 --map tcp://0.0.0.0:22335:127.0.0.1:22335
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

نسخه فعلی: `0.3.0`
