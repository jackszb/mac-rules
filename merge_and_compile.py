import json
import ssl
import subprocess
import urllib.request
import urllib.error
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
    "https://raw.githubusercontent.com/jackszb/rules-build/main/rules-src/foreign.json",
]

REJECT_URLS = [
    "https://raw.githubusercontent.com/jackszb/mac-rules/main/reject_custom_rules.json",
    "https://raw.githubusercontent.com/jackszb/sukka-clean/main/reject-I.json",
    "https://raw.githubusercontent.com/jackszb/sukka-clean/main/reject-II.json",
    "https://raw.githubusercontent.com/jackszb/clean/main/adblocksingbox.json",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Singbox.json",
]

IP_URLS = [
    "https://raw.githubusercontent.com/jackszb/cn-ip/main/rules/geoip-cn.json",
    "https://raw.githubusercontent.com/jackszb/mac-rules/main/ip_custom_rules.json",
]

# 允许输出的字段(源数据里只会出现 ip_cidr,不存在单独的 ip 字段)
ALLOWED_KEYS = {
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "ip_cidr",
}

# 网络请求超时时间(秒)
FETCH_TIMEOUT = 15
# sing-box 编译超时时间(秒)
COMPILE_TIMEOUT = 60


# -----------------------------
# Fetch & merge
# -----------------------------

def process_urls(urls, ssl_context):
    master_rules = {}
    dropped_keys = set()

    for url in urls:
        url = url.strip()
        if not url:
            continue

        try:
            print(f"  Fetching: {url}")

            with urllib.request.urlopen(url, context=ssl_context, timeout=FETCH_TIMEOUT) as response:
                raw = response.read().decode("utf-8")

            data = json.loads(raw)

            if not (isinstance(data, dict) and isinstance(data.get("rules"), list)):
                print(f"  [WARN] {url}: unexpected structure, no 'rules' list found, skipped")
                continue

            for rule in data["rules"]:
                if not isinstance(rule, dict):
                    print(f"  [WARN] {url}: rule entry is not an object, skipped ({rule!r})")
                    continue

                for key, value in rule.items():
                    if key not in ALLOWED_KEYS:
                        dropped_keys.add(key)
                        continue

                    master_rules.setdefault(key, [])

                    if isinstance(value, list):
                        master_rules[key].extend(value)
                    else:
                        master_rules[key].append(value)

        except urllib.error.URLError as e:
            print(f"  [NETWORK ERROR] {url}: {e}")
        except json.JSONDecodeError as e:
            print(f"  [JSON ERROR] {url}: invalid JSON ({e})")
        except Exception as e:
            print(f"  [ERROR] {url}: {e}")

    if dropped_keys:
        print(f"  [INFO] Ignored unknown/unsupported keys from this batch: {sorted(dropped_keys)}")

    return master_rules


# -----------------------------
# IP SORT (核心新增逻辑)
# -----------------------------

def sort_ip_list(values):
    ipv4 = []
    ipv6 = []

    seen = set()

    for v in values:
        if not isinstance(v, str):
            continue

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


def safe_sorted_unique(values, field_name):
    """对普通字符串字段做去重排序,过滤掉非字符串类型并给出警告,避免 sorted() 因类型混杂而抛错。"""
    str_values = []
    non_str_count = 0

    for v in values:
        if isinstance(v, str):
            str_values.append(v)
        else:
            non_str_count += 1

    if non_str_count:
        print(f"  [WARN] field '{field_name}': dropped {non_str_count} non-string value(s)")

    return sorted(set(str_values))


# -----------------------------
# Save JSON + compile SRS
# -----------------------------

def save_json_and_compile(master_rules, json_file, srs_file):
    final_rule = {}

    # 先处理普通 domain 类字段
    domain_like_keys = ALLOWED_KEYS - {"ip_cidr"}
    for key in domain_like_keys:
        values = master_rules.get(key)
        if not values:
            continue
        final_rule[key] = safe_sorted_unique(values, key)

    # ip_cidr 走专门的 IPv4/IPv6 排序去重逻辑
    ip_values = master_rules.get("ip_cidr")
    if ip_values:
        final_rule["ip_cidr"] = sort_ip_list(ip_values)

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
            text=True,
            timeout=COMPILE_TIMEOUT,
        )

        if result.returncode == 0:
            print(f"  SRS compiled: {srs_file}")
        else:
            print(f"  [SRS ERROR]: {result.stderr}")

    except FileNotFoundError:
        print("  [WARNING] sing-box not found, only JSON generated")
    except subprocess.TimeoutExpired:
        print(f"  [SRS ERROR]: compile timed out after {COMPILE_TIMEOUT}s")


# -----------------------------
# MAIN
# -----------------------------

def main():
    # 使用默认的证书校验上下文(raw.githubusercontent.com 证书有效,无需关闭校验)
    ssl_context = ssl.create_default_context()

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
