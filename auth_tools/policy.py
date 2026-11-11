"""
Account rules that keep external identities and CTFd passwords apart.

- External accounts (upstream header or OIDC) can't log in with a
  password, and can't set one. Otherwise a user provisioned by the proxy could
  set a password in Settings and then log in without going through the proxy.
- In upstream header mode, self-registration is closed (unless allowed by setting): the
  proxy is the only way accounts are created, so nobody can register a name
  ahead of the person whose identity carries it.

Accounts created through CTFd itself (e.g. the admin from the setup wizard)
are unaffected and keep using their password.
"""

from flask import abort, jsonify, redirect, render_template, request, session, url_for

from CTFd.cache import clear_user_session
from CTFd.exceptions.email import UserResetPasswordTokenInvalidException
from CTFd.models import Users, db
from CTFd.utils import validators
from CTFd.utils.config import is_setup
from CTFd.utils.logging import log
from CTFd.utils.security.email import verify_reset_password_token
from CTFd.utils.user import authed, get_current_user

from . import config
from .header_auth import is_header_session
from .models import AuthIdentity

LOGIN_BLOCKED = "This account does not support password sign-on"
# User-facing messages are deliberately method-neutral: the reverse proxy might
# use mTLS, an SSO gateway, or anything else that sets the header.
PASSWORD_BLOCKED = "Sign-on for this account is managed externally and does not use passwords"
EMAIL_LOCKED = "Your email is externally managed and cannot be changed"
RESET_REQUESTED = "If that account exists you will receive an email, please check your inbox"
REGISTRATION_CLOSED = "Accounts are created automatically when you log in."


def linked_identity(user):
    if user is None:
        return None
    return AuthIdentity.query.filter_by(user_id=user.id).first()


def _login_user_lookup(name):
    # Mirrors CTFd's own lookup in auth.login.
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
                "[{date}] {ip} - auth_tools refused password login for external account {name}",
                name=user.name,
            )
            return render_template(
                "login.html", errors=[LOGIN_BLOCKED]
            )

    elif endpoint == "api.users_user_private" and request.method == "PATCH":
        data = request.get_json(silent=True) or {}
        user = get_current_user()
        identity = linked_identity(user)
        if identity is not None:
            if data.get("password"):
                return jsonify(
                    {"success": False, "errors": {"password": [PASSWORD_BLOCKED]}}
                ), 400
            if "email" in data:
                submitted = data["email"] or None
                # CTFd's core theme renders a missing email as the text "None".
                if submitted == "None" and user.email is None:
                    submitted = None
                if submitted != user.email:
                    return jsonify({"success": False, "errors": {"email": [EMAIL_LOCKED]}}), 400
                # Unchanged: drop it. CTFd treats a blank email on an account with
                # no email as a change that needs the current password, which
                # these accounts don't have, so the whole save would fail.
                # (get_json() is cached, so CTFd's view sees this same dict.)
                data.pop("email")

    elif endpoint == "api.users_user_public" and request.method == "PATCH":
        # Admins editing a user: external accounts can't be given a password, and
        # can't be forced to change one (that would lock them out: CTFd would
        # send them to a password reset they're not allowed to complete).
        # Admins can still change everything else, including the email.
        data = request.get_json(silent=True) or {}
        wants_password = bool(data.get("password"))
        wants_change = str(data.get("change_password", "")).lower() in ("true", "1", "y", "on")
        if wants_password or wants_change:
            target = Users.query.filter_by(id=(request.view_args or {}).get("user_id")).first()
            identity = linked_identity(target)
            if identity is not None:
                field = "password" if wants_password else "change_password"
                return jsonify({"success": False, "errors": {field: [PASSWORD_BLOCKED]}}), 400

    elif endpoint == "auth.reset_password":
        # An external account flagged "require password change" (e.g. before this
        # rule existed) would be sent here on every request and could never
        # finish. Clear the flag and let them in.
        current = get_current_user() if authed() else None
        if current is not None and current.change_password and linked_identity(current):
            current.change_password = False
            db.session.commit()
            clear_user_session(user_id=current.id)
            session.pop("reset_password", None)
            return redirect(url_for("challenges.listing"))

        token = (request.view_args or {}).get("data")
        if token is None:
            # Requesting a reset link: don't send one to an external account. Reply
            # exactly as CTFd does for unknown addresses, so this doesn't reveal
            # which emails belong to external accounts.
            if request.method == "POST":
                user = Users.query.filter_by(
                    email=request.form.get("email", "").strip()
                ).first()
                if linked_identity(user) is not None:
                    return render_template("reset_password.html", infos=[RESET_REQUESTED])
        else:
            # Using a reset link (e.g. one sent before the account was linked).
            try:
                address = verify_reset_password_token(token)
            except UserResetPasswordTokenInvalidException:
                return  # CTFd shows its own "invalid link" error
            if linked_identity(Users.query.filter_by(email=address).first()) is not None:
                return render_template("reset_password.html", errors=[LOGIN_BLOCKED])

    elif endpoint == "auth.logout":
        # The proxy would log a header session straight back in, so don't bother.
        if config.get("header_hide_logout") and is_header_session():
            return redirect(url_for("challenges.listing"))

    elif endpoint == "auth.register":
        if config.get("mode") == "header" and not config.get("header_allow_registration"):
            abort(403, description=REGISTRATION_CLOSED)
