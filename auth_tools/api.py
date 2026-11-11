"""
Admin-only API for listing external accounts.

    GET /api/v1/auth_tools/identities
        ?via=header|oidc   only reverse-proxy or only OpenID accounts
        &user_id=<int>     one CTFd user
        &subject=<str>     exact external ID (header value or OIDC "sub")

Works with an admin browser session or a CTFd API token:

    curl -H "Authorization: Token ctfd_..." -H "Content-Type: application/json" \
         https://ctfd.example.com/api/v1/auth_tools/identities?via=header
"""

from flask import Blueprint, jsonify, request

from CTFd.models import Users
from CTFd.utils.user import is_admin

from .header_auth import PROVIDER as HEADER_PROVIDER
from .models import AuthIdentity

api = Blueprint("auth_tools_api", __name__)


def _error(status, message):
    return jsonify({"success": False, "errors": [message]}), status


def serialize(identity):
    user = identity.user
    return {
        "id": identity.id,
        "via": "header" if identity.provider == HEADER_PROVIDER else "oidc",
        "provider": identity.provider,
        "subject": identity.subject,
        "user_id": user.id,
        "name": user.name,
        "email": user.email,
        "type": user.type,
        "banned": bool(user.banned),
        "hidden": bool(user.hidden),
        "created": user.created.isoformat() + "Z" if user.created else None,
    }


@api.route("/api/v1/auth_tools/identities")
def list_identities():
    if not is_admin():
        return _error(403, "Admins only.")

    query = AuthIdentity.query.join(Users, Users.id == AuthIdentity.user_id)

    via = request.args.get("via")
    if via == "header":
        query = query.filter(AuthIdentity.provider == HEADER_PROVIDER)
    elif via == "oidc":
        query = query.filter(AuthIdentity.provider != HEADER_PROVIDER)
    elif via:
        return _error(400, "via must be 'header' or 'oidc'.")

    user_id = request.args.get("user_id")
    if user_id:
        try:
            query = query.filter(AuthIdentity.user_id == int(user_id))
        except ValueError:
            return _error(400, "user_id must be an integer.")

    subject = request.args.get("subject")
    if subject:
        query = query.filter(AuthIdentity.subject == subject)

    identities = query.order_by(AuthIdentity.user_id, AuthIdentity.id).all()
    return jsonify(
        {
            "success": True,
            "data": [serialize(i) for i in identities],
            "meta": {"count": len(identities)},
        }
    )
