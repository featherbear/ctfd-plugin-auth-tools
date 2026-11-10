"""Tests for the auth_tools plugin. See README.md ("Tests") for how to run them."""

import base64
import json
import time
from urllib.parse import parse_qs, urlparse

import pytest

from CTFd.models import Users
from tests.helpers import create_ctfd, destroy_ctfd, gen_user, login_as_user

PROXY = {"REMOTE_ADDR": "127.0.0.1"}
OUTSIDE = {"REMOTE_ADDR": "203.0.113.9"}


@pytest.fixture
def app(monkeypatch):
    for k in list(__import__("os").environ):
        if k.startswith("AUTH_TOOLS_"):
            monkeypatch.delenv(k)
    app = create_ctfd(enable_plugins=True)
    yield app
    destroy_ctfd(app)


def identities(app):
    from CTFd.plugins.auth_tools.models import AuthIdentity

    with app.app_context():
        return [(i.provider, i.subject, i.user_id) for i in AuthIdentity.query.all()]


# --------------------------------------------------------------------------
# Header auth
# --------------------------------------------------------------------------


@pytest.fixture
def header_env(monkeypatch):
    monkeypatch.setenv("AUTH_TOOLS_MODE", "header")


def test_header_disabled_by_default(app):
    with app.test_client() as c:
        c.get("/challenges", headers={"X-Auth-ID": "alice"}, environ_base=PROXY)
        with c.session_transaction() as s:
            assert "id" not in s
    assert identities(app) == []


def test_header_creates_and_reuses_user(app, header_env):
    with app.test_client() as c:
        r = c.get("/challenges", headers={"X-Auth-ID": "alice"}, environ_base=PROXY)
        assert r.status_code == 200
        with c.session_transaction() as s:
            uid = s["id"]
    with app.app_context():
        u = Users.query.filter_by(id=uid).first()
        assert u.name == "alice" and u.verified and u.password is None and u.email is None
    # Second client, same identity -> same user, no duplicate
    with app.test_client() as c:
        c.get("/challenges", headers={"X-Auth-ID": "alice"}, environ_base=PROXY)
        with c.session_transaction() as s:
            assert s["id"] == uid
    assert identities(app) == [("header", "alice", uid)]


def test_header_survives_rename(app, header_env):
    with app.test_client() as c:
        c.get("/", headers={"X-Auth-ID": "alice"}, environ_base=PROXY)
        with c.session_transaction() as s:
            uid = s["id"]
    with app.app_context():
        from CTFd.models import db

        Users.query.filter_by(id=uid).first().name = "renamed"
        db.session.commit()
    with app.test_client() as c:
        c.get("/", headers={"X-Auth-ID": "alice"}, environ_base=PROXY)
        with c.session_transaction() as s:
            assert s["id"] == uid


def test_header_name_collision_gets_suffix(app, header_env):
    with app.app_context():
        from CTFd.models import db

        gen_user(db, name="bob", email="bob@example.com")
    with app.test_client() as c:
        c.get("/", headers={"X-Auth-ID": "bob"}, environ_base=PROXY)
    with app.app_context():
        assert Users.query.filter_by(name="bob-2").count() == 1


def test_header_ignored_from_untrusted_peer(app, header_env):
    with app.test_client() as c:
        c.get("/challenges", headers={"X-Auth-ID": "mallory"}, environ_base=OUTSIDE)
        with c.session_transaction() as s:
            assert "id" not in s
    assert identities(app) == []


def test_header_ignores_x_forwarded_for_spoof(app, header_env, monkeypatch):
    # Even with ProxyFix rewriting remote_addr, the socket peer is checked.
    monkeypatch.setenv("AUTH_TOOLS_HEADER_TRUSTED_PROXIES", "10.0.0.1/32")
    from werkzeug.middleware.proxy_fix import ProxyFix

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)
    with app.test_client() as c:
        c.get(
            "/",
            headers={"X-Auth-ID": "mallory", "X-Forwarded-For": "10.0.0.1"},
            environ_base=OUTSIDE,
        )
        with c.session_transaction() as s:
            assert "id" not in s
        c.get("/", headers={"X-Auth-ID": "carol"}, environ_base={"REMOTE_ADDR": "10.0.0.1"})
        with c.session_transaction() as s:
            assert "id" in s


def test_header_switch_identity_and_logout_on_missing(app, header_env):
    with app.test_client() as c:
        c.get("/", headers={"X-Auth-ID": "alice"}, environ_base=PROXY)
        with c.session_transaction() as s:
            alice = s["id"]
        c.get("/", headers={"X-Auth-ID": "bob"}, environ_base=PROXY)
        with c.session_transaction() as s:
            assert s["id"] != alice
        c.get("/", environ_base=PROXY)
        with c.session_transaction() as s:
            assert "id" not in s


def test_header_does_not_logout_password_sessions(app, header_env):
    with app.app_context():
        from CTFd.models import db

        gen_user(db, name="user", email="user@example.com")
    client = login_as_user(app)
    client.get("/", environ_base=PROXY)
    with client.session_transaction() as s:
        assert "id" in s


def test_header_subject_regex(app, header_env, monkeypatch):
    monkeypatch.setenv("AUTH_TOOLS_HEADER_SUBJECT_REGEX", r"(?:^|,)CN=(?P<id>[^,]+)")
    with app.test_client() as c:
        c.get("/", headers={"X-Auth-ID": "CN=dave,OU=Players,O=CTF"}, environ_base=PROXY)
    assert [i[1] for i in identities(app)] == ["dave"]
    with app.test_client() as c:
        r = c.get("/", headers={"X-Auth-ID": "OU=nocn"}, environ_base=PROXY)
        assert r.status_code == 403


def test_header_no_auto_create(app, header_env, monkeypatch):
    monkeypatch.setenv("AUTH_TOOLS_HEADER_AUTO_CREATE", "false")
    with app.test_client() as c:
        r = c.get("/", headers={"X-Auth-ID": "alice"}, environ_base=PROXY)
        assert r.status_code == 403


def test_header_banned_user(app, header_env):
    with app.test_client() as c:
        c.get("/", headers={"X-Auth-ID": "alice"}, environ_base=PROXY)
        with c.session_transaction() as s:
            uid = s["id"]
    with app.app_context():
        from CTFd.models import db

        Users.query.filter_by(id=uid).first().banned = True
        db.session.commit()
    with app.test_client() as c:
        r = c.get("/challenges", headers={"X-Auth-ID": "alice"}, environ_base=PROXY)
        assert r.status_code == 403


# --------------------------------------------------------------------------
# OIDC
# --------------------------------------------------------------------------

ISSUER = "https://idp.example.com"
CLIENT_ID = "ctfd"


class FakeResp:
    def __init__(self, data, status=200):
        self._data, self.status_code = data, status

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise __import__("requests").HTTPError(str(self.status_code))


def b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


class FakeIdP:
    def __init__(self, claims=None, userinfo=None):
        self.claims = claims or {}
        self.userinfo = userinfo
        self.nonce = None
        self.token_calls = []

    def get(self, url, **kw):
        if url.endswith("/.well-known/openid-configuration"):
            return FakeResp(
                {
                    "issuer": ISSUER,
                    "authorization_endpoint": ISSUER + "/authorize",
                    "token_endpoint": ISSUER + "/token",
                    "userinfo_endpoint": ISSUER + "/userinfo",
                }
            )
        if url == ISSUER + "/userinfo":
            return FakeResp(self.userinfo or {"sub": self.claims.get("sub", "sub-1")})
        raise AssertionError(url)

    def post(self, url, data=None, auth=None, **kw):
        assert url == ISSUER + "/token"
        self.token_calls.append((data, auth))
        claims = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "sub-1",
            "exp": time.time() + 300,
            "nonce": self.nonce,
        }
        claims.update(self.claims)
        token = "e30." + b64(claims) + ".sig"
        return FakeResp({"id_token": token, "access_token": "at", "token_type": "Bearer"})


@pytest.fixture
def idp(monkeypatch):
    monkeypatch.setenv("AUTH_TOOLS_MODE", "oidc")
    monkeypatch.setenv("AUTH_TOOLS_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("AUTH_TOOLS_OIDC_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("AUTH_TOOLS_OIDC_CLIENT_SECRET", "secret")
    fake = FakeIdP()
    import CTFd.plugins.auth_tools.oidc as oidc_mod

    oidc_mod._discovery_cache.clear()
    monkeypatch.setattr(oidc_mod.requests, "get", fake.get)
    monkeypatch.setattr(oidc_mod.requests, "post", fake.post)
    return fake


def run_flow(c, idp, state_override=None, next_url=None):
    r = c.get("/auth_tools/oidc/login" + (("?next=" + next_url) if next_url else ""))
    assert r.status_code == 302
    loc = urlparse(r.headers["Location"])
    q = {k: v[0] for k, v in parse_qs(loc.query).items()}
    assert loc.path == "/authorize" and q["code_challenge_method"] == "S256"
    idp.nonce = q["nonce"]
    return c.get(
        "/auth_tools/oidc/callback?code=abc&state=" + (state_override or q["state"])
    )


def test_oidc_creates_user(app, idp):
    idp.claims = {"preferred_username": "frank", "email": "f@example.com", "email_verified": True}
    with app.test_client() as c:
        r = run_flow(c, idp, next_url="/scoreboard")
        assert r.status_code == 302 and r.headers["Location"].endswith("/scoreboard")
        with c.session_transaction() as s:
            uid = s["id"]
    with app.app_context():
        u = Users.query.filter_by(id=uid).first()
        assert (u.name, u.email) == ("frank", "f@example.com")
    assert identities(app) == [(ISSUER, "sub-1", uid)]
    data, auth = idp.token_calls[0]
    assert auth == ("ctfd", "secret") and data["code_verifier"]


def test_oidc_unverified_email_not_stored(app, idp):
    idp.claims = {"preferred_username": "gina", "email": "g@example.com", "email_verified": False}
    with app.test_client() as c:
        run_flow(c, idp)
    with app.app_context():
        assert Users.query.filter_by(name="gina").first().email is None


def test_oidc_state_mismatch(app, idp):
    with app.test_client() as c:
        r = run_flow(c, idp, state_override="wrong")
        assert r.headers["Location"].endswith("/login")
        with c.session_transaction() as s:
            assert "id" not in s


@pytest.mark.parametrize(
    "bad",
    [{"aud": "other"}, {"iss": "https://evil.example.com"}, {"exp": 1}, {"nonce": "x"}],
)
def test_oidc_bad_id_token(app, idp, bad):
    with app.test_client() as c:
        c.get("/auth_tools/oidc/login")
        with c.session_transaction() as s:
            pending = s["auth_tools_oidc"]
        idp.nonce = pending["nonce"]
        idp.claims = bad
        r = c.get("/auth_tools/oidc/callback?code=abc&state=" + pending["state"])
        assert r.headers["Location"].endswith("/login")
        with c.session_transaction() as s:
            assert "id" not in s


def test_oidc_never_links_existing_accounts(app, idp, monkeypatch):
    # Users can change their CTFd email, so a matching email must never hand an
    # existing password account to an OIDC identity. The removed setting has no effect.
    monkeypatch.setenv("AUTH_TOOLS_OIDC_LINK_BY_VERIFIED_EMAIL", "true")
    with app.app_context():
        from CTFd.models import db

        existing = gen_user(db, name="hank", email="h@example.com").id
    idp.claims = {"preferred_username": "hank", "email": "h@example.com", "email_verified": True}
    with app.test_client() as c:
        run_flow(c, idp)
        with c.session_transaction() as s:
            new_id = s["id"]
    assert new_id != existing
    with app.app_context():
        new = Users.query.filter_by(id=new_id).first()
        old = Users.query.filter_by(id=existing).first()
        assert new.name == "hank-2" and new.email is None  # email belongs to the other account
        assert old.password is not None  # password account untouched
    r, uid = _password_login(app, "hank", "password")
    assert uid == existing  # and it still logs in with its password


def test_oidc_open_redirect_blocked(app, idp):
    with app.test_client() as c:
        r = run_flow(c, idp, next_url="https://evil.example.com/")
        assert "evil" not in r.headers["Location"]


def test_login_js_and_admin_page(app, idp):
    with app.test_client() as c:
        js = c.get("/plugins/auth_tools/site.js").get_data(as_text=True)
        assert '"enabled": true' in js and "/auth_tools/oidc/login" in js
        assert '"toggleText": "Sign in with username / email"' in js
        assert "__AUTH_TOOLS_CONFIG__" not in js
        assert "/plugins/auth_tools/site.js" in c.get("/login").get_data(as_text=True)
    admin = login_as_user(app, name="admin")
    r = admin.get("/admin/auth_tools")
    assert r.status_code == 200 and "AUTH_TOOLS_OIDC_ISSUER" in r.get_data(as_text=True)
    with admin.session_transaction() as s:
        nonce = s["nonce"]
    r = admin.post(
        "/admin/auth_tools",
        data={"nonce": nonce, "header_name": "X-Client-DN", "mode": "header"},
    )
    assert r.status_code == 302
    with app.app_context():
        from CTFd.plugins.auth_tools import config

        assert config.get("header_name") == "X-Client-DN"
        # env-locked values are not overwritten
        assert config.get("mode") == "oidc"
        assert config.get("oidc_issuer") == ISSUER


def test_subjects_are_case_sensitive(app, header_env):
    # MySQL/MariaDB default collations are case-insensitive; the identity
    # columns use a binary collation so distinct subjects never collide.
    with app.test_client() as c:
        c.get("/", headers={"X-Auth-ID": "aBc"}, environ_base=PROXY)
        with c.session_transaction() as s:
            first = s["id"]
    with app.test_client() as c:
        c.get("/", headers={"X-Auth-ID": "AbC"}, environ_base=PROXY)
        with c.session_transaction() as s:
            assert s["id"] != first
    assert sorted(i[1] for i in identities(app)) == ["AbC", "aBc"]


# --------------------------------------------------------------------------
# Mode: only one login method at a time
# --------------------------------------------------------------------------


def test_header_ignored_in_oidc_mode(app, idp):
    with app.test_client() as c:
        c.get("/challenges", headers={"X-Auth-ID": "alice"}, environ_base=PROXY)
        with c.session_transaction() as s:
            assert "id" not in s
    assert identities(app) == []


def test_oidc_unavailable_in_header_mode(app, idp, monkeypatch):
    monkeypatch.setenv("AUTH_TOOLS_MODE", "header")
    with app.test_client() as c:
        r = c.get("/auth_tools/oidc/login")
        assert r.status_code == 302 and r.headers["Location"].endswith("/login")
        js = c.get("/plugins/auth_tools/site.js").get_data(as_text=True)
        assert '"enabled": false' in js


def test_switching_mode_ends_header_sessions(app, header_env, monkeypatch):
    with app.test_client() as c:
        c.get("/", headers={"X-Auth-ID": "alice"}, environ_base=PROXY)
        with c.session_transaction() as s:
            assert "id" in s
        monkeypatch.setenv("AUTH_TOOLS_MODE", "oidc")
        c.get("/", headers={"X-Auth-ID": "alice"}, environ_base=PROXY)
        with c.session_transaction() as s:
            assert "id" not in s


def test_mode_set_from_admin_page(app):
    from CTFd.plugins.auth_tools import config

    admin = login_as_user(app, name="admin")
    for posted, expected in [("header", "header"), ("oidc", "oidc"), ("bogus", "off")]:
        with admin.session_transaction() as s:
            nonce = s["nonce"]
        admin.post("/admin/auth_tools", data={"nonce": nonce, "mode": posted})
        with app.app_context():
            assert config.get("mode") == expected
    assert "<select" in admin.get("/admin/auth_tools").get_data(as_text=True)


def test_unknown_mode_fails_closed(app, monkeypatch):
    monkeypatch.setenv("AUTH_TOOLS_MODE", "both")
    with app.test_client() as c:
        c.get("/", headers={"X-Auth-ID": "alice"}, environ_base=PROXY)
        with c.session_transaction() as s:
            assert "id" not in s


# --------------------------------------------------------------------------
# Account policy: linked accounts and passwords, registration in header mode
# --------------------------------------------------------------------------


def _set_password_via_api(c, password, **kw):
    # CTFd's test client adds the CSRF-Token header for JSON requests itself.
    return c.patch("/api/v1/users/me", json={"password": password}, **kw)


def _password_login(app, name, password):
    with app.test_client() as c:
        c.get("/login")
        with c.session_transaction() as s:
            nonce = s["nonce"]
        r = c.post("/login", data={"name": name, "password": password, "nonce": nonce})
        with c.session_transaction() as s:
            return r, s.get("id")


def test_header_user_cannot_set_password(app, header_env):
    # The reproduced attack: set a password via Settings, then log in without a cert.
    with app.test_client() as c:
        c.get("/", headers={"X-Auth-ID": "bob"}, environ_base=PROXY)
        r = _set_password_via_api(
            c, "bob-has-a-password", headers={"X-Auth-ID": "bob"}, environ_base=PROXY
        )
        assert r.status_code == 400
        assert r.get_json()["errors"]["password"] == ["Sign-on for this account is managed externally and does not use passwords"]
    with app.app_context():
        assert Users.query.filter_by(name="bob").first().password is None
    r, uid = _password_login(app, "bob", "bob-has-a-password")
    assert uid is None


def test_linked_account_password_login_refused_even_with_password(app, header_env):
    # e.g. an admin set a password on the account, or it was linked by email.
    with app.test_client() as c:
        c.get("/", headers={"X-Auth-ID": "bob"}, environ_base=PROXY)
    with app.app_context():
        from CTFd.models import db

        Users.query.filter_by(name="bob").first().password = "pw"
        db.session.commit()
    r, uid = _password_login(app, "bob", "pw")
    assert uid is None and b"This account does not support password sign-on" in r.data
    r, uid = _password_login(app, "bob@nowhere.invalid", "pw")  # email path too
    assert uid is None


def test_oidc_linked_account_password_login_refused(app, idp):
    idp.claims = {"preferred_username": "frank", "email": "f@example.com", "email_verified": True}
    with app.test_client() as c:
        run_flow(c, idp)
    with app.app_context():
        from CTFd.models import db

        Users.query.filter_by(name="frank").first().password = "pw"
        db.session.commit()
    r, uid = _password_login(app, "f@example.com", "pw")
    assert uid is None and b"This account does not support password sign-on" in r.data


def test_regular_accounts_keep_password_login(app, header_env):
    r, uid = _password_login(app, "admin", "password")
    assert uid is not None
    with app.app_context():
        from CTFd.models import db

        gen_user(db, name="regular", email="regular@example.com")
    client = login_as_user(app, name="regular")
    r = _set_password_via_api(client, "new-password-123")
    assert r.status_code == 400  # CTFd: a user with a password must confirm it
    assert "confirm" in json.dumps(r.get_json())  # ...but not blocked by the plugin
    with client.session_transaction() as s:
        assert s.get("id")


def test_registration_closed_in_header_mode(app, header_env, monkeypatch):
    with app.test_client() as c:
        r = c.get("/register")
        assert r.status_code == 403
        assert b"Accounts are created automatically when you sign in." in r.data
    monkeypatch.setenv("AUTH_TOOLS_HEADER_ALLOW_REGISTRATION", "true")
    with app.test_client() as c:
        assert c.get("/register").status_code == 200


def test_registration_open_in_oidc_mode(app, idp):
    with app.test_client() as c:
        assert c.get("/register").status_code == 200


def test_header_never_reuses_existing_accounts(app, header_env, monkeypatch):
    # Users can change their CTFd name and email, so neither proves who they are.
    # The removed header_link_by setting has no effect.
    monkeypatch.setenv("AUTH_TOOLS_HEADER_LINK_BY", "email")
    monkeypatch.setenv("AUTH_TOOLS_HEADER_EMAIL_HEADER", "X-Auth-Email")
    with app.app_context():
        from CTFd.models import db

        gwen = gen_user(db, name="gwen", email="gwen@example.com").id
    for ident, email, existing_name in [
        ("gwen", "gwen@example.com", "gwen"),  # same name and same email
        ("admin", "admin@examplectf.com", "admin"),  # the setup admin's name and email
    ]:
        with app.test_client() as c:
            c.get("/", headers={"X-Auth-ID": ident, "X-Auth-Email": email}, environ_base=PROXY)
            with c.session_transaction() as s:
                uid = s["id"]
        with app.app_context():
            new = Users.query.filter_by(id=uid).first()
            assert new.name == existing_name + "-2" and new.email is None
            assert new.type == "user"
    r, uid = _password_login(app, "gwen", "password")
    assert uid == gwen  # the existing account is untouched


# --------------------------------------------------------------------------
# Admin API: GET /api/v1/auth_tools/identities
# --------------------------------------------------------------------------

API = "/api/v1/auth_tools/identities"


@pytest.fixture
def linked(app, header_env, idp):
    """alice and bob via the header, frank via OIDC, plus an unlinked user."""
    import os

    for name in ("alice", "bob"):
        os.environ["AUTH_TOOLS_MODE"] = "header"
        with app.test_client() as c:
            c.get("/", headers={"X-Auth-ID": name}, environ_base=PROXY)
    os.environ["AUTH_TOOLS_MODE"] = "oidc"
    idp.claims = {"sub": "oidc-frank", "preferred_username": "frank"}
    with app.test_client() as c:
        run_flow(c, idp)
    with app.app_context():
        from CTFd.models import db

        gen_user(db, name="plain", email="plain@example.com")
    return app


def test_api_lists_linked_accounts(linked):
    admin = login_as_user(linked, name="admin")
    body = admin.get(API).get_json()
    assert body["success"] and body["meta"]["count"] == 3
    rows = {r["name"]: r for r in body["data"]}
    assert set(rows) == {"alice", "bob", "frank"}  # not admin, not "plain"
    assert rows["alice"]["via"] == "header" and rows["alice"]["subject"] == "alice"
    assert rows["frank"]["via"] == "oidc" and rows["frank"]["provider"] == ISSUER
    assert rows["frank"]["subject"] == "oidc-frank"
    assert set(rows["alice"]) == {
        "id", "via", "provider", "subject", "user_id", "name", "email",
        "type", "banned", "hidden", "created",
    }


def test_api_filters(linked):
    admin = login_as_user(linked, name="admin")
    names = lambda q: sorted(r["name"] for r in admin.get(API + q).get_json()["data"])
    assert names("?via=header") == ["alice", "bob"]
    assert names("?via=oidc") == ["frank"]
    assert names("?subject=bob") == ["bob"]
    uid = admin.get(API + "?subject=bob").get_json()["data"][0]["user_id"]
    assert names("?user_id=%d" % uid) == ["bob"]
    assert admin.get(API + "?via=ldap").status_code == 400
    assert admin.get(API + "?user_id=abc").status_code == 400


def test_api_is_admin_only(linked):
    with linked.test_client() as anon:
        r = anon.get(API)
        assert r.status_code == 403 and r.get_json()["success"] is False
    user = login_as_user(linked, name="plain")
    assert user.get(API).status_code == 403


def test_api_accepts_admin_token(linked):
    from CTFd.utils.security.auth import generate_user_token

    with linked.app_context():
        admin = Users.query.filter_by(name="admin").first()
        token = generate_user_token(admin, expiration=None).value
        plain = Users.query.filter_by(name="plain").first()
        user_token = generate_user_token(plain, expiration=None).value
    with linked.test_client() as c:
        hdrs = {"Authorization": "Token " + token, "Content-Type": "application/json"}
        r = c.get(API, headers=hdrs)
        assert r.status_code == 200 and r.get_json()["meta"]["count"] == 3
    with linked.test_client() as c:
        hdrs = {"Authorization": "Token " + user_token, "Content-Type": "application/json"}
        assert c.get(API, headers=hdrs).status_code == 403


# --------------------------------------------------------------------------
# Settings page: descriptions and choices
# --------------------------------------------------------------------------


def test_settings_page_descriptions_and_choices(app):
    from CTFd.plugins.auth_tools import config

    admin = login_as_user(app, name="admin")
    html = admin.get("/admin/auth_tools").get_data(as_text=True)
    for key, setting in config.SETTINGS.items():
        assert setting.description, key
        assert 'id="%s-help"' % key in html
    assert "Reverse-proxy header (e.g. mTLS)" in html
    assert "client_secret_post" in html
    assert "Valid values" in html


@pytest.mark.parametrize(
    "key,value,expected",
    [
        ("mode", "HEADER", "header"),
        ("mode", "both", "off"),
        ("oidc_token_auth_method", "private_key_jwt", "client_secret_basic"),
    ],
)
def test_choice_settings_fail_closed(app, monkeypatch, key, value, expected):
    from CTFd.plugins.auth_tools import config

    monkeypatch.setenv(config.env_name(key), value)
    with app.app_context():
        assert config.get(key) == expected


# --------------------------------------------------------------------------
# Hiding Log out for header (mTLS) sessions
# --------------------------------------------------------------------------

CSS = "/plugins/auth_tools/session.css"
ALICE = {"headers": {"X-Auth-ID": "alice"}, "environ_base": PROXY}


def test_header_session_hides_logout(app, header_env):
    with app.test_client() as c:
        page = c.get("/challenges", **ALICE).get_data(as_text=True)
        assert CSS in page  # stylesheet is linked from every page
        css = c.get(CSS, **ALICE).get_data(as_text=True)
        assert 'a[href="/logout"]' in css and "display:none" in css
        assert 'li:has(> a[href="/logout"])' in css


def test_header_session_logout_is_noop(app, header_env):
    with app.test_client() as c:
        c.get("/", **ALICE)
        r = c.get("/logout", **ALICE)
        assert r.status_code == 302 and r.headers["Location"].endswith("/challenges")
        with c.session_transaction() as s:
            assert s.get("auth_tools_header_subject") == "alice"


def test_password_session_keeps_logout(app, header_env):
    admin = login_as_user(app, name="admin")
    assert admin.get(CSS, environ_base=PROXY).get_data(as_text=True) == ""
    admin.get("/logout", environ_base=PROXY)
    with admin.session_transaction() as s:
        assert "id" not in s


def test_hide_logout_can_be_disabled(app, header_env, monkeypatch):
    monkeypatch.setenv("AUTH_TOOLS_HEADER_HIDE_LOGOUT", "false")
    with app.test_client() as c:
        assert c.get(CSS, **ALICE).get_data(as_text=True) == ""
        c.get("/logout", **ALICE)
        with c.session_transaction() as s:
            assert "id" not in s


def test_oidc_session_keeps_logout(app, idp):
    with app.test_client() as c:
        run_flow(c, idp)
        assert c.get(CSS).get_data(as_text=True) == ""


# --------------------------------------------------------------------------
# Linked accounts can't get a password by any route
# --------------------------------------------------------------------------


def _oidc_user(app, idp, email="o@example.com"):
    idp.claims = {"preferred_username": "olive", "email": email, "email_verified": True}
    with app.test_client() as c:
        run_flow(c, idp)
        with c.session_transaction() as s:
            return s["id"]


@pytest.fixture
def mail(app, monkeypatch):
    """Pretend CTFd can send email, and record reset emails instead of sending."""
    from CTFd.utils import set_config

    sent = []
    with app.app_context():
        set_config("mail_server", "smtp.example.com")
        set_config("mail_port", 25)
        set_config("mailfrom_addr", "ctf@example.com")
    monkeypatch.setattr("CTFd.utils.email.forgot_password", lambda addr: sent.append(addr))
    return sent


def _post_form(c, url, **data):
    c.get(url)
    with c.session_transaction() as s:
        data["nonce"] = s["nonce"]
    return c.post(url, data=data)


def test_reset_link_not_sent_to_linked_account(app, idp, mail):
    _oidc_user(app, idp)
    with app.app_context():
        from CTFd.models import db

        gen_user(db, name="regular", email="regular@example.com")
    with app.test_client() as c:
        r = _post_form(c, "/reset_password", email="o@example.com")
        assert b"If that account exists" in r.data  # same reply as an unknown address
        _post_form(c, "/reset_password", email="regular@example.com")
    assert mail == ["regular@example.com"]


def test_existing_reset_link_refused_for_linked_account(app, idp, mail):
    from CTFd.cache import cache

    uid = _oidc_user(app, idp)
    with app.app_context():
        cache.set("reset_password_tok123", "o@example.com")
    with app.test_client() as c:
        r = _post_form(c, "/reset_password/tok123", password="new-password-123")
        assert b"This account does not support password sign-on" in r.data
    with app.app_context():
        assert Users.query.filter_by(id=uid).first().password is None


def test_admin_cannot_set_password_on_linked_account(app, idp):
    uid = _oidc_user(app, idp)
    with app.app_context():
        from CTFd.models import db

        regular = gen_user(db, name="regular", email="regular@example.com").id
    admin = login_as_user(app, name="admin")
    r = admin.patch("/api/v1/users/%d" % uid, json={"password": "admin-set-pw"})
    assert r.status_code == 400
    assert r.get_json()["errors"]["password"] == ["Sign-on for this account is managed externally and does not use passwords"]
    with app.app_context():
        assert Users.query.filter_by(id=uid).first().password is None
    # Other edits to the linked account, and passwords for normal accounts, still work.
    assert admin.patch("/api/v1/users/%d" % uid, json={"affiliation": "x"}).status_code == 200
    assert admin.patch("/api/v1/users/%d" % regular, json={"password": "pw-12345"}).status_code == 200


def test_admin_badge_script(app):
    with app.test_client() as anon:
        assert anon.get("/plugins/auth_tools/admin.js").status_code in (302, 403)
    admin = login_as_user(app, name="admin")
    assert "/plugins/auth_tools/admin.js" in admin.get("/admin/users").get_data(as_text=True)
    js = admin.get("/plugins/auth_tools/admin.js").get_data(as_text=True)
    assert "auth-tools-signin" in js and "/api/v1/auth_tools/identities" in js


# --------------------------------------------------------------------------
# Settings page: password and email locked for linked accounts
# --------------------------------------------------------------------------

SITE_JS = "/plugins/auth_tools/site.js"


def test_site_js_marks_linked_accounts(app, header_env, monkeypatch):
    monkeypatch.setenv("AUTH_TOOLS_HEADER_EMAIL_HEADER", "X-Auth-Email")
    hdrs = {"X-Auth-ID": "alice", "X-Auth-Email": "alice@example.com"}
    with app.test_client() as c:
        js = c.get(SITE_JS, headers=hdrs, environ_base=PROXY).get_data(as_text=True)
        assert '"linked": true' in js and '"settingsPath": "/settings"' in js
        assert "Your email is externally managed and cannot be changed" in js
    admin = login_as_user(app, name="admin")
    assert '"linked": false' in admin.get(SITE_JS, environ_base=PROXY).get_data(as_text=True)
    with app.test_client() as anon:
        assert '"linked": false' in anon.get(SITE_JS).get_data(as_text=True)


def test_linked_account_cannot_change_email(app, header_env, monkeypatch):
    monkeypatch.setenv("AUTH_TOOLS_HEADER_EMAIL_HEADER", "X-Auth-Email")
    kw = {"headers": {"X-Auth-ID": "alice", "X-Auth-Email": "alice@example.com"}, "environ_base": PROXY}
    with app.test_client() as c:
        c.get("/", **kw)
        r = c.patch("/api/v1/users/me", json={"email": "new@example.com"}, **kw)
        assert r.status_code == 400
        assert r.get_json()["errors"]["email"] == ["Your email is externally managed and cannot be changed"]
        # Saving the form unchanged (same email) still works for other fields.
        r = c.patch("/api/v1/users/me", json={"email": "alice@example.com", "affiliation": "Team A"}, **kw)
        assert r.status_code == 200
    with app.app_context():
        u = Users.query.filter_by(name="alice").first()
        assert u.email == "alice@example.com" and u.affiliation == "Team A"


def test_linked_account_without_email_stays_without(app, idp):
    idp.claims = {"preferred_username": "nomail"}  # provider sent no email
    with app.test_client() as c:
        run_flow(c, idp)
        r = c.patch("/api/v1/users/me", json={"email": "", "website": "https://x.example"})
        assert r.status_code == 200
        r = c.patch("/api/v1/users/me", json={"email": "added@example.com"})
        assert r.status_code == 400
        # CTFd's core theme submits a missing email as the text "None".
        r = c.patch("/api/v1/users/me", json={"email": "None", "affiliation": "Team N"})
        assert r.status_code == 200


# --------------------------------------------------------------------------
# "Require password change" can't trap linked accounts
# --------------------------------------------------------------------------


def test_admin_cannot_require_password_change_on_linked_account(app, idp):
    uid = _oidc_user(app, idp)
    with app.app_context():
        from CTFd.models import db

        regular = gen_user(db, name="regular", email="regular@example.com").id
    admin = login_as_user(app, name="admin")
    r = admin.patch("/api/v1/users/%d" % uid, json={"change_password": True})
    assert r.status_code == 400 and "change_password" in r.get_json()["errors"]
    with app.app_context():
        assert not Users.query.filter_by(id=uid).first().change_password
    # Admins can still change a linked account's email, and use the flag on normal accounts.
    r = admin.patch("/api/v1/users/%d" % uid, json={"email": "fixed@example.com"})
    assert r.status_code == 200
    r = admin.patch("/api/v1/users/%d" % regular, json={"change_password": True})
    assert r.status_code == 200


def test_flagged_linked_account_is_not_locked_out(app, header_env):
    with app.test_client() as c:
        c.get("/", **ALICE)
    with app.app_context():
        from CTFd.models import db

        Users.query.filter_by(name="alice").first().change_password = True  # e.g. set before the fix
        db.session.commit()
    from CTFd.cache import clear_user_session

    with app.app_context():
        clear_user_session(user_id=Users.query.filter_by(name="alice").first().id)
    with app.test_client() as c:
        c.get("/", **ALICE)  # logs in; CTFd's check runs before the header login
        r = c.get("/challenges", follow_redirects=True, **ALICE)  # CTFd redirects to reset
        assert r.status_code == 200 and r.request.path == "/challenges"
        assert c.get("/scoreboard", **ALICE).status_code == 200  # and stays unblocked
    with app.app_context():
        assert not Users.query.filter_by(name="alice").first().change_password
