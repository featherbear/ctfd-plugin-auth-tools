"""Runs CTFd's first-time setup wizard over HTTP so the stack is usable immediately."""

import os
import re
import sys
import time
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

BASE = os.environ.get("CTFD_URL", "http://ctfd:8000")
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))

for _ in range(60):
    try:
        page = opener.open(BASE + "/setup").read().decode()
        break
    except OSError:
        time.sleep(2)
else:
    sys.exit("CTFd did not come up")

match = re.search(r"csrfNonce['\"]?\s*:\s*\"([0-9a-f]+)\"", page)
if not match or "/setup" not in page:
    print("CTFd is already set up.")
    sys.exit(0)

form = {
    "ctf_name": "Auth Tools Dev",
    "ctf_description": "Local test instance for the auth_tools plugin",
    "user_mode": "users",
    "name": os.environ.get("ADMIN_NAME", "admin"),
    "email": os.environ.get("ADMIN_EMAIL", "admin@example.com"),
    "password": os.environ.get("ADMIN_PASSWORD", "password"),
    "ctf_theme": "core",
    "nonce": match.group(1),
}
opener.open(BASE + "/setup", data=urllib.parse.urlencode(form).encode()).read()
print("CTFd setup complete. Admin: {name} / {password}".format(**form))
