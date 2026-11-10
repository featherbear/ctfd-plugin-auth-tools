"""
Reverse-proxy header authentication (e.g. mTLS terminated at nginx/Envoy).

The proxy verifies the client and passes an identity in a header (default
``X-Auth-ID``). On each request we map that value to a CTFd user and keep the
Flask session in sync with it.

The header is only trusted when the TCP peer is in ``header_trusted_proxies``.
The proxy MUST
strip or overwrite any client-supplied copy of the header.
"""

import ipaddress
import re
from functools import lru_cache

from flask import abort, request, session

from CTFd.utils.config import is_setup
from CTFd.utils.logging import log
from CTFd.utils.security.auth import login_user, logout_user

from . import config
from .provisioning import ProvisioningError, resolve_user

PROVIDER = "header"
SESSION_SUBJECT = "auth_tools_header_subject"
SESSION_UID = "auth_tools_header_uid"


@lru_cache(maxsize=16)
def _networks(spec):
    nets = []
    for part in spec.split(","):
        part = part.strip()
        if part:
            nets.append(ipaddress.ip_network(part, strict=False))
    return tuple(nets)


@lru_cache(maxsize=16)
def _regex(pattern):
    return re.compile(pattern)


def peer_address():
    """The socket peer, ignoring any X-Forwarded-For rewriting by ProxyFix."""
    orig = request.environ.get("werkzeug.proxy_fix.orig") or {}
    return orig.get("REMOTE_ADDR") or request.environ.get("REMOTE_ADDR")


def from_trusted_proxy():
    addr = peer_address()
    if not addr:
        return False
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return any(ip in net for net in _networks(config.get("header_trusted_proxies")))


def extract_subject(raw):
    raw = (raw or "").strip()
    pattern = config.get("header_subject_regex")
    if not raw or not pattern:
        return raw or None
    match = _regex(pattern).search(raw)
    if not match:
        return None
    if "id" in match.re.groupindex:
        value = match.group("id")
    elif match.re.groups:
        value = match.group(1)
    else:
        value = match.group(0)
    return (value or "").strip() or None


def is_header_session():
    """True when the current session was created by the identity header."""
    return (
        config.get("mode") == "header"
        and session.get(SESSION_SUBJECT) is not None
        and session.get("id") is not None
        and session.get("id") == session.get(SESSION_UID)
    )


def _drop_header_session():
    if session.get(SESSION_SUBJECT) is not None:
        logout_user()


def header_auth_hook():
    if config.get("mode") != "header" or not is_setup():
        # A session created while header mode was on must not outlive it.
        _drop_header_session()
        return

    raw = request.headers.get(config.get("header_name"))
    if raw and not from_trusted_proxy():
        log(
            "logins",
            "[{date}] {ip} - auth_tools ignored identity header from untrusted peer {peer}",
            peer=peer_address(),
        )
        raw = None

    if not raw:
        if config.get("header_logout_on_missing"):
            _drop_header_session()
        return

    subject = extract_subject(raw)
    if subject is None:
        _drop_header_session()
        abort(403, description="Client identity was not accepted.")

    # Fast path: session already belongs to this identity.
    if (
        session.get(SESSION_SUBJECT) == subject
        and session.get("id") is not None
        and session.get("id") == session.get(SESSION_UID)
    ):
        return

    email_header = config.get("header_email_header")
    try:
        user = resolve_user(
            PROVIDER,
            subject,
            email=request.headers.get(email_header) if email_header else None,
            auto_create=config.get("header_auto_create"),
            link_by=config.get("header_link_by"),
        )
    except ProvisioningError as e:
        _drop_header_session()
        abort(403, description=str(e))

    if user.banned:
        _drop_header_session()
        abort(403, description="You have been banned from this CTF")

    logout_user()
    login_user(user)
    session[SESSION_SUBJECT] = subject
    session[SESSION_UID] = user.id
    log(
        "logins",
        "[{date}] {ip} - auth_tools header login for {name} ({subject})",
        name=user.name,
        subject=subject,
    )
