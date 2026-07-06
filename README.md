## 🎯 Why this scanner?

When you hide your server behind Cloudflare (CDN relay), the edge IP your client connects to **directly impacts speed and stability**.  
This tool scans the entire Cloudflare IP range **from your network’s perspective** (through a local proxy) and gives you:

- **Top‑N IPs** with the lowest latency **and** lowest jitter – not just raw ping.
- IPs grouped **by country** – ready to paste into V2Ray, Xray, Sing‑Box, Nekoray, and more.
- Fully **adaptive** fetching (direct first, proxy fallback) – works even behind strict firewalls.

No more guessing, no more random IP lists. **Get the real clean IPs that work best for you.**

---

## ✨ Features

| Feature | Description |
|--------|-------------|
| 🔍 **Adaptive fetching** | Download Cloudflare IP ranges directly, fallback to proxy if blocked. |
| 🧪 **Real‑world quality test** | TCP ping (via your proxy) measures **average latency + jitter**, not ICMP. |
| 🧵 **High concurrency** | Scan hundreds of IPs simultaneously without breaking. |
| 🌍 **Country classification** | Auto‑tags each working IP with its country using ip‑api.com. |
| 📁 **Ready‑to‑use output** | `All.txt` + per‑country files in clean comma‑space format (`1.1.1.1, 2.2.2.2`). |
| 🛡️ **Crash‑safe** | Atomic writes, graceful Ctrl+C saves progress, nothing is lost. |
| ⚙️ **SOCKS5 & HTTP proxy support** | Test through any proxy (local or remote). |
| 🚀 **IPv6 support** | Optional scanning of Cloudflare IPv6 ranges. |

---

## 🚀 Quick Start

```bash
git clone https://github.com/yourusername/cloudflare-relay-scanner.git
cd cloudflare-relay-scanner
pip install -r requirements.txt
python scanner.py
```
##📋 Requirements

    Python 3.8+

    aiohttp

    rich

    (Optional) aiohttp-socks if you use a SOCKS5 proxy.

##🛠️ Usage

python scanner.py \
  --proxy socks5://127.0.0.1:10808 \
  --max-ping 200 \
  --max-jitter 30 \
  --top 20 \
  --output-dir MyResults \
  --concurrency 200

##Key Arguments
Flag	Description	Default
-p, --proxy	Proxy for latency testing (http or socks5)	http://127.0.0.1:10809
-t, --timeout	Connection timeout (seconds)	3.0
-m, --max-ping	Maximum average latency (ms)	300
--max-jitter	Maximum allowed jitter (ms)	50
--min-success	Minimum successful pings per IP	2
--ping-count	Total ping attempts per IP	4
-C, --concurrency	Max simultaneous connections	150
--top N	Keep only the N best IPs	All
--include-ipv6	Scan IPv6 ranges as well	False
--output-dir	Where to save results	Result
📂 Output Structure
text

Result/
├── All.txt               ← All valid IPs: 104.16.0.1, 104.16.1.1, ...
├── Germany.txt           ← German IPs
├── United_States.txt     ← US IPs
├── Netherlands.txt
└── ...

Just open a file, copy the line, and paste it into your outbound or address field. No extra formatting needed.
🔧 Use Cases

    V2Ray / Xray + Cloudflare + WebSocket/TLS – replace address with these IPs.

    Nekoray / Sing‑Box – custom outbound with CDN relay IP.

    Hide your real server behind Cloudflare while keeping the best possible route.

    Avoid ISP throttling by switching to a high‑quality edge IP.
