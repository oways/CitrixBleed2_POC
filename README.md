# CitrixBleed2 POC - Memory Disclosure PoC (CVE-2025-5777)

This proof-of-concept (PoC) exploits a vulnerability in certain Citrix Gateway or NetScaler devices where the headers in a POST request to the authentication endpoint causes memory leakage in the XML response.

The leaked data may contain:
- Internal log lines (e.g., SSL handshakes, AAA messages)
- Internal IP addresses
- Cookie fragments (`Set-Cookie`)
- Partial XML or HTML output
- Sensitive memory data

> ⚠️ This issue may indicate an **information disclosure vulnerability** and could aid in chaining with other attacks (like XSS or session hijacking).

---

## 🔧 Usage

```bash
python3 CitrixBleed2.py https://target-citrix.com 100
```

Where:

    https://target-citrix.com is the Citrix Gateway/NetScaler host.

    100 is the number of random header values to iterate from 1 to 100.

> 🧪 Example Output

```
[*] Target: https://target-citrix.com/p/u/doAuthentication.do
[*] Trying 100 requests

======== random=31 ========
[+] InitialValue found:
default SSLLOG SSL_HANDSHAKE_SUCCESS 9400562 ... ClientIP 10.xx.xx.xx

======== random=59 ========
[+] Cookie found:
Set-Cookie: NSC_USER=anything;Path=/;Secure
```

> 📌 Notes

    SSL verification is disabled by default (verify=False) to support testing on internal targets.

    The User-Agent field is extended to trigger deeper memory behavior.

> ⚠️ Disclaimer

This PoC is provided for educational and authorized testing purposes only. Unauthorized use against production environments without consent is strictly prohibited.

> Reference:
https://labs.watchtowr.com/how-much-more-must-we-bleed-citrix-netscaler-memory-disclosure-citrixbleed-2-cve-2025-5777/

---

## ☕ To Support My Projects

If this PoC was helpful, consider sponsoring my projects or following me on GitHub.

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-%E2%9D%A4-lightgrey?logo=github)](https://github.com/sponsors/oways)
[![Buy Me a Coffee](https://img.shields.io/badge/☕-Buy%20Me%20a%20Coffee-yellow)](https://buymeacoffee.com/0ways)
