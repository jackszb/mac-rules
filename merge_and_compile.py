import json
import ssl
import subprocess
import urllib.request
import ipaddress

# -----------------------------
# URL LISTS
# -----------------------------

DIRECT_URLS = [
    "https://raw.githubusercontent.com/jackszb/rules-build/main/rules-src/direct.json",
    "https://raw.githubusercontent.com/jackszb/mac-rules/main/direct_custom_rules.json",
]

PROXY_URLS = [
    "https://raw.githubusercontent.com/jackszb/rules-build/main/rules-src/proxy.json",
]

REJECT_URLS = [
    "https://raw.githubusercontent.com/jackszb/iphone-rules/main/reject_custom_rules.json",
    "https://raw.githubusercontent.com/jackszb/sukka-clean/main/reject-I.json",
    "https://raw.githubusercontent.com/jackszb/sukka-clean/main/reject-II.json",
    "https://raw.githubusercontent.com/jackszb/clean/main/adblocksingbox.json",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Singbox.json",
]

IP_URLS = [
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/ip/china_ip.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/ip/domestic.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/ip/china_ip_ipv6.json",
    "https://raw.githubusercontent.com/jackszb/mac-rules/main/ip_custom_rules.json",
]

# -----------------------------
# Fetch & merge
# -----------------------------

def process_urls(urls, ssl_context):
    master_rules = {}

    for url in urls:
        url = url.strip()
        if not url:
            continue

        try:
            print(f"  Fetching: {url}")

            with urllib.request.urlopen(url, context=ssl_context) as response:
                data = json.loads(response.read().decode("utf-8"))

            if "rules" in data and isinstance(data["rules"], list):
                for rule in data["rules"]:
                    for key, value in rule.items():
                        master_rules.setdefault(key, [])

                        if isinstance(value, list):
                            master_rules[key].extend(value)
                        else:
                            master_rules[key].append(value)

        except Exception as e:
            print(f"  [ERROR] {url}: {e}")

    return master_rules


# -----------------------------
# IP SORT (核心新增逻辑)
# -----------------------------

def sort_ip_list(values):
    ipv4 = []
    ipv6 = []

    seen = set()

    for v in values:
        if v in seen:
            continue
        seen.add(v)

        try:
            ip_obj = ipaddress.ip_network(v, strict=False)

            if isinstance(ip_obj, ipaddress.IPv4Network):
                ipv4.append(ip_obj)
            else:
                ipv6.append(ip_obj)

        except Exception:
            # 如果不是合法 IP，直接忽略（避免崩）
            continue

    ipv4_sorted = sorted(ipv4, key=lambda x: (int(x.network_address), x.prefixlen))
    ipv6_sorted = sorted(ipv6, key=lambda x: (int(x.network_address), x.prefixlen))

    return [str(x) for x in ipv4_sorted + ipv6_sorted]


# -----------------------------
# Save JSON + compile SRS
# -----------------------------

def save_json_and_compile(master_rules, json_file, srs_file):
    final_rule = {}

    allowed_keys = {
        "domain",
        "domain_suffix",
        "domain_keyword",
        "domain_regex",
        "ip_cidr",
        "ip"
    }

    for key, values in master_rules.items():
        if not values:
            continue

        if key in allowed_keys:

            # ✅ IP 特殊处理：IPv4 → IPv6
            if key in ("ip", "ip_cidr"):
                final_rule[key] = sort_ip_list(values)
            else:
                final_rule[key] = sorted(set(values))

    data = {
        "version": 4,
        "rules": [final_rule]
    }

    # -----------------------------
    # SAVE JSON
    # -----------------------------
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"  JSON saved: {json_file}")

    # -----------------------------
    # COMPILE SRS
    # -----------------------------
    try:
        result = subprocess.run(
            ["sing-box", "rule-set", "compile", "--output", srs_file, json_file],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            print(f"  SRS compiled: {srs_file}")
        else:
            print(f"  [SRS ERROR]: {result.stderr}")

    except FileNotFoundError:
        print("  [WARNING] sing-box not found, only JSON generated")


# -----------------------------
# MAIN
# -----------------------------

def main():
    ssl_context = ssl._create_unverified_context()

    print("\n=== DIRECT ===")
    direct = process_urls(DIRECT_URLS, ssl_context)
    save_json_and_compile(direct, "direct_rules.json", "direct_rules.srs")

    print("\n=== PROXY ===")
    proxy = process_urls(PROXY_URLS, ssl_context)
    save_json_and_compile(proxy, "proxy_rules.json", "proxy_rules.srs")

    print("\n=== REJECT ===")
    reject = process_urls(REJECT_URLS, ssl_context)
    save_json_and_compile(reject, "reject_rules.json", "reject_rules.srs")

    print("\n=== IP ===")
    ip = process_urls(IP_URLS, ssl_context)
    save_json_and_compile(ip, "ip_rules.json", "ip_rules.srs")

    print("\n=== ALL DONE ===")


if __name__ == "__main__":
    main()
