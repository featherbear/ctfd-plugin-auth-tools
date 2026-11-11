"""
OpenID Connect login (authorization code flow with PKCE).

No third-party JWT library is needed: the ID token is received directly from
the token endpoint over TLS using client authentication, so per OIDC Core
3.1.3.7 (6) TLS server validation stands in for signature checking. All other
claim checks (iss, aud, azp, exp, nonce) are still performed.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
from urllib.parse import quote, urlencode, urlparse

import requests
from flask import Blueprint, redirect, request, session, url_for

from CTFd.utils.helpers import error_for
from CTFd.utils.logging import log
from CTFd.utils.security.auth import login_user, logout_user
from CTFd.utils.validators import is_safe_url

from . import config
from .provisioning import ProvisioningError, resolve_user

oidc = Blueprint("auth_tools_oidc", __name__)

SESSION_PENDING = "auth_tools_oidc"
HTTP_TIMEOUT = 10
CLOCK_SKEW = 120
DISCOVERY_TTL = 3600

_discovery_cache = {}


class OIDCError(Exception):
    pass


def enabled():
    return bool(
        config.get("mode") == "oidc"
        and config.get("oidc_issuer")
        and config.get("oidc_client_id")
    )


def _require_https(url):
    if config.get("oidc_allow_http"):
        return
    if urlparse(url).scheme != "https":
        raise OIDCError("OIDC endpoint must use https: {}".format(url))


def discovery():
    issuer = config.get("oidc_issuer").rstrip("/")
    cached = _discovery_cache.get(issuer)
    if cached and cached[0] > time.time():
        return cached[1]

    url = issuer + "/.well-known/openid-configuration"
    _require_https(url)
    resp = requests.get(url, timeout=HTTP_TIMEOUT)
    resp.raise_for_status()
    doc = resp.json()
    if doc.get("issuer", "").rstrip("/") != issuer:
        raise OIDCError("Discovery issuer mismatch: {}".format(doc.get("issuer")))
    for key in ("authorization_endpoint", "token_endpoint"):
        if not doc.get(key):
            raise OIDCError("Discovery document missing {}".format(key))
        _require_https(doc[key])

    _discovery_cache[issuer] = (time.time() + DISCOVERY_TTL, doc)
    return doc


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _redirect_uri():
    return config.get("oidc_redirect_uri") or url_for(
        "auth_tools_oidc.callback", _external=True
    )


def _fail(message):
    log("logins", "[{date}] {ip} - auth_tools OIDC failure: {msg}", msg=message)
    error_for(endpoint="auth.login", message=message)
    return redirect(url_for("auth.login"))


def _validate_id_token(id_token, issuer, nonce):
    try:
        _, payload, _ = id_token.split(".")
        claims = json.loads(_b64url_decode(payload))
    except (ValueError, TypeError):
        raise OIDCError("Malformed ID token.")

    client_id = config.get("oidc_client_id")
    if str(claims.get("iss", "")).rstrip("/") != issuer.rstrip("/"):
        raise OIDCError("ID token issuer mismatch.")
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if client_id not in auds:
        raise OIDCError("ID token audience mismatch.")
    if len(auds) > 1 and claims.get("azp") != client_id:
        raise OIDCError("ID token authorized party mismatch.")
    try:
        exp = float(claims["exp"])
    except (KeyError, TypeError, ValueError):
        raise OIDCError("ID token has no valid expiry.")
    if exp < time.time() - CLOCK_SKEW:
        raise OIDCError("ID token has expired.")
    if not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
        raise OIDCError("ID token nonce mismatch.")
    if not claims.get("sub"):
        raise OIDCError("ID token has no subject.")
    return claims


def _exchange_code(doc, code, verifier):
    client_id = config.get("oidc_client_id")
    client_secret = config.get("oidc_client_secret")
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": _redirect_uri(),
        "code_verifier": verifier,
    }
    auth = None
    if config.get("oidc_token_auth_method") == "client_secret_post" or not client_secret:
        data["client_id"] = client_id
        if client_secret:
            data["client_secret"] = client_secret
    else:
        # RFC 6749 2.3.1: form-encode credentials before Basic auth.
        auth = (quote(client_id, safe=""), quote(client_secret, safe=""))

    resp = requests.post(
        doc["token_endpoint"],
        data=data,
        auth=auth,
        headers={"Accept": "application/json"},
        timeout=HTTP_TIMEOUT,
    )
    if resp.status_code != 200:
        raise OIDCError("Token request failed ({}).".format(resp.status_code))
    return resp.json()


def _userinfo(doc, access_token, sub):
    endpoint = doc.get("userinfo_endpoint")
    if not endpoint or not access_token:
        return {}
    _require_https(endpoint)
    resp = requests.get(
        endpoint,
        headers={"Authorization": "Bearer " + access_token, "Accept": "application/json"},
        timeout=HTTP_TIMEOUT,
    )
    if resp.status_code != 200:
        return {}
    try:
        info = resp.json()
    except ValueError:
        return {}
    # OIDC Core 5.3.2: userinfo sub must match the ID token.
    if info.get("sub") != sub:
        return {}
    return info


def _truthy(value):
    return value is True or str(value).lower() == "true"


@oidc.route("/auth_tools/oidc/login")
def login():
    if not enabled():
        return _fail("OpenID Connect login is not configured.")
    try:
        doc = discovery()
    except (requests.RequestException, ValueError, OIDCError) as e:
        log("logins", "[{date}] {ip} - auth_tools OIDC discovery error: {e}", e=e)
        return _fail("Could not reach the identity provider.")

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    next_url = request.args.get("next")
    session[SESSION_PENDING] = {
        "state": state,
        "nonce": nonce,
        "verifier": verifier,
        "issuer": doc["issuer"],
        "next": next_url if next_url and is_safe_url(next_url) else None,
    }

    params = {
        "response_type": "code",
        "client_id": config.get("oidc_client_id"),
        "redirect_uri": _redirect_uri(),
        "scope": config.get("oidc_scopes") or "openid",
        "state": state,
        "nonce": nonce,
        "code_challenge": _b64url(hashlib.sha256(verifier.encode("ascii")).digest()),
        "code_challenge_method": "S256",
    }
    endpoint = doc["authorization_endpoint"]
    sep = "&" if "?" in endpoint else "?"
    return redirect(endpoint + sep + urlencode(params))


@oidc.route("/auth_tools/oidc/callback")
def callback():
    pending = session.pop(SESSION_PENDING, None)
    if not enabled():
        return _fail("OpenID Connect login is not configured.")
    if request.args.get("error"):
        return _fail(
            "Identity provider returned an error: {}".format(
                request.args.get("error_description") or request.args.get("error")
            )
        )
    state = request.args.get("state", "")
    code = request.args.get("code")
    if not pending or not hmac.compare_digest(state, pending["state"]):
        return _fail("Login session expired or state mismatch. Please try again.")
    if not code:
        return _fail("Identity provider did not return an authorization code.")

    try:
        doc = discovery()
        if doc["issuer"] != pending["issuer"]:
            raise OIDCError("Issuer changed during login.")
        tokens = _exchange_code(doc, code, pending["verifier"])
        if not tokens.get("id_token"):
            raise OIDCError("Token response had no ID token.")
        claims = _validate_id_token(tokens["id_token"], doc["issuer"], pending["nonce"])
        info = _userinfo(doc, tokens.get("access_token"), claims["sub"])
    except (requests.RequestException, ValueError, OIDCError) as e:
        log("logins", "[{date}] {ip} - auth_tools OIDC error: {e}", e=e)
        return _fail("OpenID Connect login failed. Please try again.")

    profile = dict(info)
    profile.update(claims)  # ID token claims win over userinfo

    email = profile.get("email")
    email_verified = _truthy(profile.get("email_verified"))
    name = (
        profile.get(config.get("oidc_username_claim"))
        or profile.get("preferred_username")
        or profile.get("name")
        or email
        or claims["sub"]
    )

    try:
        user = resolve_user(
            doc["issuer"].rstrip("/"),
            str(claims["sub"]),
            name=str(name),
            # Only store addresses the IdP has verified. The email is never
            # used to find an existing account (see provisioning.py).
            email=email if email_verified else None,
            auto_create=config.get("oidc_auto_create"),
        )
    except ProvisioningError as e:
        return _fail(str(e))

    if user.banned:
        return _fail("You have been banned from this CTF")

    logout_user()
    login_user(user)
    log(
        "logins",
        "[{date}] {ip} - auth_tools OIDC login for {name} ({sub})",
        name=user.name,
        sub=claims["sub"],
    )
    return redirect(pending.get("next") or url_for("challenges.listing"))
