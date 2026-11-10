"""
auth_tools: reverse-proxy header authentication and OpenID Connect login for CTFd.

Install by copying this directory to CTFd/plugins/auth_tools.
"""

import json
import os

from flask import Blueprint, Response, redirect, render_template, request, url_for

from CTFd.plugins import (
    register_admin_plugin_menu_bar,
    register_plugin_script,
    register_plugin_stylesheet,
)
from CTFd.plugins.migrations import upgrade
from CTFd.utils.decorators import admins_only

from . import config, oidc
from .api import api
from .header_auth import header_auth_hook, is_header_session
from .policy import account_policy_hook
from .models import AuthIdentity  # noqa: F401  (registers the table)

PLUGIN_NAME = "auth_tools"

admin = Blueprint("auth_tools_admin", __name__)

LOGIN_JS_PATH = os.path.join(os.path.dirname(__file__), "assets", "login.js")

GROUPS = [
    ("General", ["mode"]),
    ("Reverse-proxy header", [k for k in config.SETTINGS if k.startswith("header_")]),
    ("OpenID Connect", [k for k in config.SETTINGS if k.startswith("oidc_")]),
]


@admin.route("/admin/auth_tools", methods=["GET", "POST"])
@admins_only
def settings():
    if request.method == "POST":
        for key, setting in config.SETTINGS.items():
            kind = setting.kind
            if config.from_env(key):
                continue
            if kind == "bool":
                config.set(key, key in request.form)
            elif kind == "choice":
                config.set(key, request.form.get(key, ""))
            elif kind == "secret":
                value = request.form.get(key, "")
                if request.form.get(key + "__clear"):
                    config.set(key, "")
                elif value:
                    config.set(key, value)
            else:
                config.set(key, request.form.get(key, "").strip())
        oidc._discovery_cache.clear()
        return redirect(url_for("auth_tools_admin.settings", saved=1))

    groups = []
    for title, keys in GROUPS:
        rows = []
        for key in keys:
            setting = config.SETTINGS[key]
            value = config.get(key)
            rows.append(
                {
                    "key": key,
                    "kind": setting.kind,
                    "value": value if setting.kind != "secret" else "",
                    "is_set": bool(value),
                    "locked": config.from_env(key),
                    "env": config.env_name(key),
                    "default": setting.default,
                    "description": setting.description,
                    "choices": setting.choices,
                }
            )
        groups.append((title, rows))
    return render_template(
        "plugins/auth_tools/templates/settings.html",
        groups=groups,
        saved=request.args.get("saved"),
        callback_url=url_for("auth_tools_oidc.callback", _external=True),
    )


@admin.route("/plugins/auth_tools/login.js")
def login_js():
    """Puts the SSO button first on the login/register pages of any theme."""
    data = {
        "enabled": oidc.enabled(),
        "buttonText": config.get("oidc_button_text"),
        "toggleText": config.get("oidc_password_toggle_text"),
        "dividerText": config.get("oidc_divider_text"),
        "url": url_for("auth_tools_oidc.login"),
        "loginPath": url_for("auth.login"),
        "registerPath": url_for("auth.register"),
    }
    # Escape "<" so the JSON can't close a script context.
    payload = json.dumps(data).replace("<", "\\u003c")
    with open(LOGIN_JS_PATH, encoding="utf-8") as f:
        js = f.read().replace("__AUTH_TOOLS_CONFIG__", payload)
    resp = Response(js, mimetype="application/javascript")
    resp.headers["Cache-Control"] = "no-store"
    return resp


@admin.route("/plugins/auth_tools/session.css")
def session_css():
    """
    Per-session styles, loaded in <head> on every page. For header (mTLS)
    sessions it hides the Log out link in any theme, including links that
    client-side themes add later, without a flash before a script runs.
    """
    css = ""
    if config.get("header_hide_logout") and is_header_session():
        hrefs = [url_for("auth.logout"), url_for("auth.logout", _external=True)]
        links = ",".join("a[href=%s]" % json.dumps(h) for h in hrefs)
        parents = ",".join("li:has(> a[href=%s])" % json.dumps(h) for h in hrefs)
        css = "%s,%s{display:none!important}" % (links, parents)
    resp = Response(css, mimetype="text/css")
    resp.headers["Cache-Control"] = "no-store"
    return resp


def load(app):
    # Creates the table (create_all on SQLite, Alembic migration otherwise).
    upgrade(plugin_name=PLUGIN_NAME)

    app.register_blueprint(admin)
    app.register_blueprint(oidc.oidc)
    app.register_blueprint(api)
    app.before_request(header_auth_hook)
    app.before_request(account_policy_hook)

    register_plugin_script("/plugins/auth_tools/login.js")
    register_plugin_stylesheet("/plugins/auth_tools/session.css")
    register_admin_plugin_menu_bar(title="Auth Tools", route="/admin/auth_tools")
