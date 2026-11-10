"""
Account rules that keep external identities and CTFd passwords apart.

- Accounts linked to an external identity (header or OIDC) can't log in with a
  password, and can't set one. Otherwise a user provisioned by the proxy could
  set a password in Settings and then log in without their client certificate.
- In header mode, self-registration is closed (unless allowed by setting): the
  proxy is the only way accounts are created, so nobody can register a name
  ahead of the person whose certificate carries it.

Accounts created through CTFd itself (e.g. the admin from the setup wizard)
are unaffected and keep using their password.
"""

from flask import abort, jsonify, redirect, render_template, request, url_for

from CTFd.utils import validators
from CTFd.utils.config import is_setup
from CTFd.utils.logging import log
from CTFd.utils.user import get_current_user

from . import config
from .header_auth import is_header_session
from .models import AuthIdentity

LOGIN_BLOCKED = "This account does not support password sign-on"
PASSWORD_BLOCKED = (
    "This account signs in through {method}, so it can't have a password."
)
REGISTRATION_CLOSED = (
    "Accounts are created automatically when you connect with your client certificate."
)


def linked_identity(user):
    if user is None:
        return None
    return AuthIdentity.query.filter_by(user_id=user.id).first()


def method_name(identity):
    return "your client certificate" if identity.provider == "header" else "single sign-on"


def _login_user_lookup(name):
    # Mirrors CTFd's own lookup in auth.login.
    from CTFd.models import Users

    if validators.validate_email(name) is True:
        return Users.query.filter_by(email=name).first()
    return Users.query.filter_by(name=name).first()


def account_policy_hook():
    if not is_setup():
        return

    endpoint = request.endpoint

    if endpoint == "auth.login" and request.method == "POST":
        user = _login_user_lookup(request.form.get("name", ""))
        identity = linked_identity(user)
        if identity is not None:
            log(
                "logins",
                "[{date}] {ip} - auth_tools refused password login for linked account {name}",
                name=user.name,
            )
            return render_template(
                "login.html", errors=[LOGIN_BLOCKED]
            )

    elif endpoint == "api.users_user_private" and request.method == "PATCH":
        data = request.get_json(silent=True) or {}
        if data.get("password"):
            identity = linked_identity(get_current_user())
            if identity is not None:
                message = PASSWORD_BLOCKED.format(method=method_name(identity))
                return jsonify({"success": False, "errors": {"password": [message]}}), 400

    elif endpoint == "auth.logout":
        # The proxy would log a header session straight back in, so don't bother.
        if config.get("header_hide_logout") and is_header_session():
            return redirect(url_for("challenges.listing"))

    elif endpoint == "auth.register":
        if config.get("mode") == "header" and not config.get("header_allow_registration"):
            abort(403, description=REGISTRATION_CLOSED)
