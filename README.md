<div dir="rtl">

# NETIFAY

پنل وب ساخت و مدیریت تانل بین سرور داخلی (ایران) و خارج — ۹ موتور تانل، لینک GRE / IPIP / 6to4 / AmneziaWG، کلاینت V2Ray / OpenVPN / WireGuard، سایت و گواهی SSL، بکاپ و راهنمای کامل داخل پنل. یک فایل پایتون، بدون پکیج اضافه.

**زبان‌ها:** فارسی · English · 中文 · Русский — [English](#english) · [中文](#中文) · [Русский](#русский)

## نصب (یک خط)

روی **هر دو سرور** (ایران و خارج) با کاربر root بزنید:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/NETplusiran/NETIFAY/main/install.sh)
```

پورت، مسیر مخفی، نام کاربری و رمز (حداقل ۸ کاراکتر) را وارد کنید؛ آدرس پنل نمایش داده می‌شود. بعد از نصب، منو همیشه با این دستور باز می‌شود:

```bash
netifay
```

| گزینه | کار |
|---|---|
| 1 | نصب / به‌روزرسانی از گیت‌هاب (تنظیمات و تانل‌ها حفظ می‌شوند) |
| 2 | نمایش آدرس پنل |
| 3 | تغییر نام کاربری و رمز |
| 4 | ری‌استارت پنل |
| 5 | لاگ پنل |
| 6 | حذف پنل (تانل‌ها، کلاینت‌ها و سایت‌ها کار می‌کنند و حذف نمی‌شوند) |
| 7 | روشن/خاموش کردن دسترسی وب از بیرون |
| 8 | روشن/خاموش کردن HTTPS |

**پیش‌نیاز:** Ubuntu 20.04 به بالا (توزیع‌های دبیان‌پایه با apt هم کار می‌کنند ولی کمتر تست شده‌اند)، دسترسی root، Python 3.8+. برای MPTCP و حالت «کل خروجی یک سرویس» کرنل 5.6+ و cgroup v2 (Ubuntu 22.04 به بالا) لازم است.

## موتورهای تانل

| موتور | جهت اتصال | حالت‌ها | مناسب برای |
|---|---|---|---|
| **Backhaul** (پیشنهادی، tcpmux) | خارج ← ایران | لینک، مستقیم، CDN کلادفلر | بیشتر سرورها، کاربر زیاد، پنهان کردن IP پشت CDN |
| **Rathole** | خارج ← ایران | لینک | سرور ضعیف، سبک‌ترین |
| **FRP** | خارج ← ایران | لینک، مستقیم | پایداری، kcp/quic برای خط پرافت |
| **Gost** | ایران ← خارج | لینک، مستقیم | ترنسپورت‌های متنوع (tls / grpc / ws / ...) |
| **Hysteria2** (+FEC، +Fake TCP) | ایران ← خارج | لینک، مستقیم | خط پرافت؛ با Fake TCP وقتی UDP بسته است |
| **Xray Reverse** (VLESS + REALITY، +MPTCP) | خارج ← ایران | لینک، مستقیم | بیشترین مخفی‌کاری؛ تجمیع چند IP |
| **iptables** | ایران ← خارج | لینک، مستقیم | کمترین سربار، بدون برنامه اضافه |
| **تانل DNS** (dnstt) | ایران ← خارج | مستقیم | اضطراری، وقتی فقط DNS باز است |
| **تانل ICMP** (pingtunnel) | ایران ← خارج | مستقیم | اضطراری، وقتی فقط پینگ باز است |

**نوع لینک شبکه:** GRE · IPIP · 6to4 · **AmneziaWG** (وایرگارد رمزنگاری‌شده و مبهم که DPI تشخیصش نمی‌دهد). لینک بر اساس دامنه ساخته می‌شود و با عوض شدن IP خودکار به‌روز می‌شود.

## امکانات

- **مدیریت تانل:** ساخت، ویرایش، کلون، حذف، ری‌استارت زمان‌بندی‌شده، لاگ، تست پینگ لینک و تست واقعی پورت‌ها تا سرویس مقصد
- **جلوگیری از تداخل:** پورت تکراری بین تانل‌ها، کلاینت‌ها، سایت‌ها و پورت پنل؛ شبکه داخلی تکراری؛ دو لینک هم‌نوع به یک سرور؛ دکمه «بررسی تداخل‌ها»
- **تانل تو در تو:** ایران ← سرور واسط ← چند پنل؛ IP پنل‌ها از ایران دیده نمی‌شود
- **کلاینت** (بدون سرور خارج، فقط با یک کانفیگ V2Ray / OpenVPN / WireGuard):
  - *فوروارد پورت* به پنلی که جای دیگری است؛ فقط همان پورت‌ها از VPN رد می‌شوند
  - *خروجی اینترنت* برای پنل فروش روی همین سرور (مثلا 3x-ui / سنایی): پورت SOCKS روی 127.0.0.1، یا کل خروجی سرویس x-ui؛ اگر کانفیگ قطع شود ترافیک از IP سرور نشت نمی‌کند
  - SSH، مسیر اصلی سرور و بقیه تانل‌ها دست نمی‌خورند
- **SSL و سایت پوششی:** گواهی Let's Encrypt با certbot (روش HTTP یا DNS کلادفلر با ساخت خودکار رکورد A) و یک سایت ظاهری با nginx روی دامنه؛ برای XHTTP / WS / gRPC / Trojan، fallback و REALITY با دامنه خودتان
- **گواهی معتبر برای خود پنل:** پنل روی `https://دامنه` بدون هشدار مرورگر؛ مستقیم یا پشت CDN کلادفلر (پورت پنل در صورت نیاز خودکار به یکی از پورت‌های مجاز کلادفلر عوض می‌شود)؛ تمدید خودکار
- **بکاپ و بازیابی** کانفیگ تانل‌ها با بررسی هسته هر تانل و بکاپ خودکار قبل از هر بازیابی
- **هسته‌ها** همه از همین مخزن نصب می‌شوند (تب «هسته»)؛ مناسب سرورهایی که دسترسی محدود دارند
- **به‌روزرسانی از داخل پنل:** از گیت‌هاب، یا آپلود دستی `netifay.py` برای سرورهای ایران؛ اعلان نسخه جدید در صفحه اول
- **داشبورد:** تانل‌های فعال، نسخه پنل، آپتایم، ترافیک لحظه‌ای دانلود/آپلود، CPU، رم، دیسک و ترافیک هر تانل
- **بهینه‌سازی شبکه** با یک کلیک (BBR، بافرهای بزرگ‌تر، محدودیت فایل‌ها)
- **راهنمای کامل داخل پنل:** انتخاب تانل مناسب، توضیح هر موتور، ترکیب تانل‌ها، عیب‌یابی و چک‌لیست
- **رابط چهار زبانه** (فارسی، انگلیسی، چینی، روسی) با ترجمه راهنما و پیام‌ها؛ تم روز و شب؛ سازگار با موبایل

## امنیت

- بعد از نصب **HTTPS را روشن کنید** (گزینه ۸) یا از تنظیمات برای پنل گواهی دامنه بگیرید.
- مسیر مخفی بگذارید و وقتی کارتان تمام شد دسترسی وب از بیرون را ببندید (گزینه ۷).
- پنل با دسترسی root اجرا می‌شود؛ رمز قوی انتخاب کنید. ورود ناموفق محدود می‌شود.
- کانفیگ‌ها، کلیدها و فایل‌های بکاپ فقط برای root قابل خواندن ذخیره می‌شوند؛ بکاپ‌ها شامل توکن تانل‌ها هستند، امن نگه‌شان دارید.

</div>

---

## English

**NETIFAY** is a web panel for building and managing tunnels between a domestic server (users connect to it) and an abroad server (the main service runs there). Pure Python 3, a single file, no pip packages.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/NETplusiran/NETIFAY/main/install.sh)
```

Run it on **both servers** as root. Afterwards open the menu with `netifay` (1 install/update · 2 show URL · 3 reset login · 4 restart · 5 logs · 6 uninstall, tunnels keep running · 7 external web access on/off · 8 HTTPS on/off).

Requirements: Ubuntu 20.04+ (other apt-based Debian systems should work but are less tested), root, Python 3.8+. MPTCP and the "whole service exit" client mode need kernel 5.6+ with cgroup v2 (Ubuntu 22.04+).

**Engines:** Backhaul (recommended, tcpmux; also Cloudflare CDN mode) · Rathole · FRP · Gost · Hysteria2 (+FEC via UDPspeeder, +Fake TCP via Phantun) · Xray Reverse (VLESS + REALITY, +MPTCP) · iptables · DNS tunnel (dnstt) · ICMP tunnel (pingtunnel).
**Network links:** GRE / IPIP / 6to4 / AmneziaWG (encrypted and obfuscated), built from domains and updated automatically when an IP changes.

**Features**
- Create, edit, clone, delete, scheduled restarts, logs, link ping test and real end-to-end port tests
- Conflict prevention across tunnels, clients, SSL sites and the panel port, plus a "Check conflicts" audit
- Nested (chained) tunnels through an intermediate server
- **Client** tab, with only a V2Ray / OpenVPN / WireGuard config and no abroad server of your own: forward ports to a panel elsewhere, or give a sales panel on the same server (e.g. 3x-ui) an internet exit (local SOCKS on 127.0.0.1, or all outgoing traffic of a systemd service). Nothing leaks from the server IP when the VPN drops; SSH and the default route are untouched.
- **SSL & decoy site:** Let's Encrypt via certbot (HTTP or Cloudflare DNS with automatic A record) and an nginx decoy website, for XHTTP / WS / gRPC / Trojan fallbacks and REALITY with your own domain
- **Panel certificate:** the panel itself on `https://your-domain` with a valid certificate, directly or behind Cloudflare CDN (the panel port is switched to a Cloudflare HTTPS port if needed); auto-renewal
- Backup and restore of tunnel configs, with a core check per tunnel and an automatic backup before every restore
- All cores installed from this repository; in-panel update from GitHub or by uploading `netifay.py`
- Dashboard: active tunnels, panel version and update notice, uptime, live download/upload, CPU, RAM, disk, per-tunnel traffic
- One-click network optimization (BBR, larger buffers, file limits)
- Complete in-panel guide; UI, guide and server messages in Persian, English, Chinese and Russian; day/night themes; mobile friendly

**Security:** turn on HTTPS (option 8) or a domain certificate right after installing, set a secret path, and close external web access when you are done (option 7). Configs, keys and backups are stored readable by root only.


---

## 中文

**NETIFAY** 是一个用于在国内服务器和国外服务器之间搭建和管理隧道的网页面板：单个 Python 文件，无需额外依赖。在**两台服务器**上以 root 运行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/NETplusiran/NETIFAY/main/install.sh)
```

之后用 `netifay` 打开菜单。支持 Backhaul（推荐）、Rathole、FRP、Gost、Hysteria2（FEC / Fake TCP）、Xray Reverse（VLESS + REALITY）、iptables、DNS 隧道和 ICMP 隧道；链路类型 GRE / IPIP / 6to4 / AmneziaWG。还提供客户端（V2Ray / OpenVPN / WireGuard）、SSL 与伪装站点、面板的有效证书（直连或 Cloudflare CDN）、备份与恢复以及完整的面板内指南。界面支持中文。安装后请立即开启 HTTPS（菜单选项 8）。

## Русский

**NETIFAY** — веб-панель для создания и управления туннелями между внутренним и зарубежным серверами: один файл Python, без дополнительных пакетов. Запустите на **обоих серверах** от root:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/NETplusiran/NETIFAY/main/install.sh)
```

Затем откройте меню командой `netifay`. Движки: Backhaul (рекомендуется), Rathole, FRP, Gost, Hysteria2 (FEC / Fake TCP), Xray Reverse (VLESS + REALITY), iptables, DNS- и ICMP-туннели; линки GRE / IPIP / 6to4 / AmneziaWG. Также есть клиент (V2Ray / OpenVPN / WireGuard), SSL и сайт-прикрытие, действительный сертификат для самой панели (напрямую или через Cloudflare CDN), резервное копирование и полное руководство в панели. Интерфейс на русском языке. Сразу после установки включите HTTPS (пункт меню 8).

---

### Cores

All cores are downloaded from this repository's release **`cores`**, which the `Update cores` GitHub Action fills from the official projects:
[rathole](https://github.com/rapiz1/rathole) ·
[Backhaul](https://github.com/Musixal/Backhaul) ·
[frp](https://github.com/fatedier/frp) ·
[gost](https://github.com/go-gost/gost) ·
[Hysteria](https://github.com/apernet/hysteria) ·
[Xray-core](https://github.com/XTLS/Xray-core) ·
[dnstt](https://www.bamsoftware.com/software/dnstt/) ·
[pingtunnel](https://github.com/esrrhs/pingtunnel) ·
[AmneziaWG](https://github.com/amnezia-vpn/amneziawg-go) ([tools](https://github.com/amnezia-vpn/amneziawg-tools)) ·
[UDPspeeder](https://github.com/wangyu-/UDPspeeder) ·
[Phantun](https://github.com/dndx/phantun).
Each core keeps its own license.

The GRE-over-domain approach is based on [Musixal/Rathole-Tunnel](https://github.com/Musixal/Rathole-Tunnel).

### License

MIT — see [LICENSE](LICENSE).

---
Font: [Vazirmatn](https://github.com/rastikerdar/vazirmatn) by Saber Rastikerdar — SIL Open Font License 1.1 (bundled inside the panel, no external CDN).
