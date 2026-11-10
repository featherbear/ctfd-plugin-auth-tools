"""
Settings for the auth_tools plugin.

Every setting can come from two places, checked in this order:

1. An environment variable named ``AUTH_TOOLS_<KEY>`` (e.g. ``AUTH_TOOLS_MODE``).
   A value set here cannot be changed from the admin panel.
2. The CTFd config table (key ``auth_tools_<key>``), edited at /admin/auth_tools.

If neither is set, the default below applies.
"""

import os
from collections import namedtuple

from CTFd.utils import get_config, set_config

PREFIX = "auth_tools_"

# kind is one of "bool", "str", "secret", "choice".
# choices: ((value, label), ...). The first choice is the safe fallback used
# when a stored value isn't one of them.
Setting = namedtuple("Setting", "default kind description choices")


def _s(default, kind, description, choices=()):
    return Setting(default, kind, description, tuple(choices))


SETTINGS = {
    "mode": _s(
        "off", "choice",
        "Which login method is active. Only one can be on at a time.",
        [
            ("off", "Off: CTFd's normal login only"),
            ("header", "Reverse-proxy header (e.g. mTLS)"),
            ("oidc", "OpenID Connect"),
        ],
    ),
    # --- Reverse-proxy header authentication ---
    "header_name": _s(
        "X-Auth-ID", "str",
        "Request header that carries the user's identity. Your proxy must set it and "
        "strip any copy sent by the client.",
    ),
    "header_email_header": _s(
        "", "str",
        "Optional header with the user's email address. Only used when an account is "
        "created or linked. Leave blank to create accounts without an email.",
    ),
    "header_trusted_proxies": _s(
        "127.0.0.1/32,::1/128", "str",
        "Comma-separated IP addresses or CIDR ranges allowed to send the identity "
        "header. Checked against the connecting address, not X-Forwarded-For.",
    ),
    "header_subject_regex": _s(
        "", "str",
        "Optional regular expression that extracts the ID from the header value. Uses "
        "the named group \"id\", else group 1, else the whole match. Example: "
        "(?:^|,)CN=(?P<id>[^,]+) takes the CN from a certificate subject.",
    ),
    "header_auto_create": _s(
        True, "bool",
        "Create a CTFd account automatically the first time an unknown ID arrives. "
        "When off, unknown IDs are refused with a 403.",
    ),
    "header_link_by": _s(
        "", "choice",
        "The first time an ID arrives, link it to an existing account instead of "
        "creating one. Never links admin accounts.",
        [
            ("", "Don't link: always create a new account"),
            ("name", "Account whose name equals the ID"),
            ("email", "Account whose email matches the email header"),
        ],
    ),
    "header_allow_registration": _s(
        False, "bool",
        "Allow CTFd's own /register page in header mode. When off, accounts only come "
        "from the proxy, so nobody can claim a name before its owner connects.",
    ),
    "header_hide_logout": _s(
        True, "bool",
        "Hide the Log out link for users signed in by the header, and make /logout do "
        "nothing for them. Logging out would only log them straight back in, because "
        "the proxy sends the header again on the next request.",
    ),
    "header_logout_on_missing": _s(
        True, "bool",
        "Log out sessions created by the header when a request arrives without it. "
        "Password sessions are not affected.",
    ),
    # --- OpenID Connect ---
    "oidc_issuer": _s(
        "", "str",
        "Issuer URL of your identity provider, e.g. https://accounts.google.com. "
        "Endpoints are read from its /.well-known/openid-configuration.",
    ),
    "oidc_client_id": _s("", "str", "Client ID registered with the identity provider."),
    "oidc_client_secret": _s(
        "", "secret", "Client secret registered with the identity provider."
    ),
    "oidc_scopes": _s(
        "openid profile email", "str",
        "Space-separated scopes to request. Must include openid.",
    ),
    "oidc_token_auth_method": _s(
        "client_secret_basic", "choice",
        "How the client secret is sent to the token endpoint. Use what your provider "
        "expects.",
        [
            ("client_secret_basic", "HTTP Basic authentication (client_secret_basic)"),
            ("client_secret_post", "In the request body (client_secret_post)"),
        ],
    ),
    "oidc_username_claim": _s(
        "preferred_username", "str",
        "Claim used as the name of new accounts. Falls back to name, then email, "
        "then sub.",
    ),
    "oidc_button_text": _s(
        "Log in with SSO", "str", "Label of the SSO button on the login and register pages."
    ),
    "oidc_password_toggle_text": _s(
        "Sign in with username / email", "str",
        "Label of the toggle that reveals CTFd's username/password form on the login page.",
    ),
    "oidc_divider_text": _s(
        "or", "str", "Text in the divider between the SSO button and the toggle."
    ),
    "oidc_redirect_uri": _s(
        "", "str",
        "Callback URL registered with the provider. Leave blank to build it from the "
        "request, which needs CTFd's REVERSE_PROXY set correctly.",
    ),
    "oidc_auto_create": _s(
        True, "bool",
        "Create a CTFd account the first time an unknown user signs in. When off, "
        "they're refused.",
    ),
    "oidc_link_by_verified_email": _s(
        False, "bool",
        "Link a first-time user to an existing account with the same email, only if "
        "the provider marks the email as verified. Never links admin accounts.",
    ),
    "oidc_allow_http": _s(
        False, "bool", "Allow plain-http provider URLs. Only for local testing."
    ),
}

_TRUE = {"1", "true", "yes", "on", "y"}


def choice_values(key):
    return tuple(value for value, _ in SETTINGS[key].choices)


def _coerce(value, kind, key=None):
    if kind == "choice":
        value = "" if value is None else str(value).strip().lower()
        allowed = choice_values(key)
        # Unknown values fail closed to the first choice.
        return value if value in allowed else allowed[0]
    if kind == "bool":
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in _TRUE
    return "" if value is None else str(value)


def env_name(key):
    return "AUTH_TOOLS_" + key.upper()


def from_env(key):
    return env_name(key) in os.environ


def get(key):
    setting = SETTINGS[key]
    if from_env(key):
        return _coerce(os.environ[env_name(key)], setting.kind, key)
    value = get_config(PREFIX + key)
    if value is None:
        return setting.default
    return _coerce(value, setting.kind, key)


def set(key, value):
    kind = SETTINGS[key].kind
    if kind in ("bool", "choice"):
        value = _coerce(value, kind, key)
    set_config(PREFIX + key, value)
