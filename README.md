<div dir="rtl">

# NETIFAY

پنل وب ساخت و مدیریت تانل بین سرور ایران و خارج — ۷ موتور تانل، لینک GRE / IPIP / 6to4، بکاپ، تست پورت و HTTPS.

## نصب (یک خط)

روی **هر دو سرور** (ایران و خارج) با کاربر root بزنید:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/NETplusiran/NETIFAY/main/install.sh)
```

پورت، مسیر مخفی، نام کاربری و رمز (حداقل ۸ کاراکتر) را وارد کنید؛ آدرس پنل نمایش داده می‌شود.
بعد از نصب، منو همیشه با دستور زیر باز می‌شود:

```bash
netifay
```

| گزینه | کار |
|---|---|
| 1 | نصب / به‌روزرسانی از گیت‌هاب (تنظیمات و تانل‌ها حفظ می‌شوند) |
| 2 | نمایش آدرس پنل |
| 3 | تغییر نام کاربری و رمز |
| 7 | روشن/خاموش کردن دسترسی وب از بیرون |
| 8 | روشن/خاموش کردن HTTPS |
| 6 | حذف پنل (تانل‌ها دست نمی‌خورند) |

## امکانات

- **موتورها:** Rathole · Backhaul · FRP · Gost · Hysteria2 · Xray Reverse (REALITY) · iptables
- **اتصال:** لینک شبکه (GRE، IPIP، 6to4) بر اساس دامنه، مستقیم، CDN کلادفلر (Backhaul)
- ساخت، ویرایش، کلون، حذف، ری‌استارت زمان‌بندی‌شده، لاگ، تست پورت‌ها
- بکاپ و بازیابی فقط کانفیگ تانل‌ها (بررسی هسته هر تانل قبل از بازیابی، بکاپ خودکار قبل از هر بازیابی)
- رابط فارسی و انگلیسی، تم روز و شب، سازگار با موبایل
- نمایش CPU / رم / دیسک و ترافیک هر تانل
- **همه هسته‌ها از همین مخزن نصب می‌شوند** (تب «هسته» در پنل)
- **جلوگیری از تداخل:** پورت تکراری بین تانل‌ها، پورت پنل، شبکه داخلی تکراری، دو لینک هم‌نوع به یک سرور، و دکمه «بررسی تداخل‌ها»
- **تانل‌ها و قابلیت‌های ویژه (2.8):**
  - **AmneziaWG** به‌عنوان نوع لینک: لینک رمزنگاری‌شده و مبهم به‌جای GRE (برای همه موتورها)
  - **FEC (UDPspeeder)** و **Fake TCP (Phantun)** برای Hysteria2: جبران افت بسته و عبور UDP به شکل TCP
  - **MPTCP** برای Xray Reverse: تجمیع چند IP/مسیر
  - **تانل DNS (dnstt)** و **تانل ICMP (pingtunnel)** برای شرایط اضطراری
- **کلاینت:** فرستادن پورت‌های سرور از داخل یک کانفیگ V2Ray (vless/vmess/trojan/ss)، OpenVPN یا WireGuard به پنل مقصد؛ فقط همان پورت‌ها از VPN رد می‌شوند و مسیر اصلی سرور و SSH دست نمی‌خورد. حالت دوم «خروجی اینترنت»: پنل فروش (مثلا سنایی) روی همین سرور است و خروجی کاربرها از کانفیگ می‌رود (پورت SOCKS روی 127.0.0.1، یا کل خروجی سرویس x-ui با OpenVPN/WireGuard)؛ اگر کانفیگ قطع شود ترافیک از IP سرور نشت نمی‌کند
- **SSL و سایت پوششی:** گرفتن گواهی Let's Encrypt با certbot (روش HTTP یا DNS کلادفلر با ساخت خودکار رکورد A)، بالا آوردن سایت ظاهری روی دامنه با nginx، تمدید و دانلود گواهی؛ برای XHTTP / WS / gRPC / Trojan و fallback در Xray
- **به‌روزرسانی از داخل پنل:** تنظیمات ← به‌روزرسانی پنل (از گیت‌هاب، یا آپلود دستی netifay.py برای سرورهای ایران)
- **صفحه راهنما** داخل پنل: توضیح کامل هر تانل، ترکیب چند تانل و عیب‌یابی

## امنیت

- بعد از نصب **HTTPS را روشن کنید** (گزینه ۸).
- وقتی کارتان تمام شد دسترسی وب از بیرون را ببندید (گزینه ۷).
- پنل با دسترسی root اجرا می‌شود؛ رمز قوی انتخاب کنید.
- فایل‌های بکاپ شامل توکن تانل‌ها هستند؛ آن‌ها را امن نگه دارید.

## وضعیت

Rathole و Backhaul (GRE) روی سرور واقعی استفاده شده‌اند. موتورهای FRP، Gost، Hysteria2، Xray Reverse، iptables و حالت CDN **آزمایشی** هستند؛ اول با یک تانل آزمایشی امتحان کنید.


</div>

---

## English

**NETIFAY** – web panel for server-to-server tunnels.
Engines: Rathole, Backhaul, FRP, Gost, Hysteria2, Xray Reverse (REALITY), iptables.
Links: GRE / IPIP / 6to4 from domains, direct, or Cloudflare CDN (Backhaul). Pure Python 3, single file.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/NETplusiran/NETIFAY/main/install.sh)
```

New in 2.8: AmneziaWG link type, FEC (UDPspeeder) and Fake TCP (Phantun) for Hysteria2, MPTCP multi-path for Xray Reverse, DNS (dnstt) and ICMP (pingtunnel) tunnels.

New in 2.7: **Client** tab – forward ports through a V2Ray link, an OpenVPN profile or a WireGuard config (policy routing: only those ports use the VPN). New in 2.9: **internet exit** mode – the sales panel (e.g. Sanaei/x-ui) on the same server sends its users' traffic out through the config (local SOCKS on 127.0.0.1, or all outgoing traffic of a systemd service with OpenVPN/WireGuard); no leak from the server IP when the VPN drops.

In-panel update: Settings → Panel update (from GitHub, or upload netifay.py on offline servers).

New in 2.6: **SSL & decoy site** tab – Let's Encrypt certificates via certbot (HTTP or Cloudflare DNS, optional A record), an nginx decoy website on the domain, renew/download certs, for XHTTP/WS/gRPC/Trojan fallbacks.

Then run `netifay` for the menu. Turn on HTTPS (option 8) right away.

### Cores

All cores are downloaded from this repository's release **`cores`**, which the
`Update cores` GitHub Action fills from the official projects:
[rathole](https://github.com/rapiz1/rathole) ·
[Backhaul](https://github.com/Musixal/Backhaul) ·
[frp](https://github.com/fatedier/frp) ·
[gost](https://github.com/go-gost/gost) ·
[Hysteria](https://github.com/apernet/hysteria) ·
[Xray-core](https://github.com/XTLS/Xray-core).
Each core keeps its own license.

The GRE-over-domain approach is based on [Musixal/Rathole-Tunnel](https://github.com/Musixal/Rathole-Tunnel).

### License

MIT — see [LICENSE](LICENSE).

---
Font: [Vazirmatn](https://github.com/rastikerdar/vazirmatn) by Saber Rastikerdar — SIL Open Font License 1.1 (bundled inside the panel, no external CDN).
