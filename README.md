# ctfd-auth-tools

A CTFd plugin (built and tested against CTFd 3.8.9) that adds two ways to log in. Only one
can be active at a time:

1. **Reverse-proxy header auth.** A trusted proxy (for example nginx doing mTLS) sends the
   client's identity in a header, `X-Auth-ID` by default. The plugin logs the request in as
   the matching CTFd user and creates the account if it doesn't exist yet.
2. **OpenID Connect login.** Uses the authorization code flow with PKCE. The login page
   shows a "Log in with SSO" button first, and CTFd's username/password form sits behind a
   "Sign in with username / email" toggle.

It has no dependencies beyond what CTFd already ships.

## Install

```sh
cp -r auth_tools /path/to/CTFd/CTFd/plugins/auth_tools
# or, with Docker, mount it:
#   -v ./auth_tools:/opt/CTFd/CTFd/plugins/auth_tools:ro
```

On startup the plugin creates the table `auth_tools_identities`. On SQLite it uses
`create_all`. On MySQL/MariaDB it runs an Alembic migration.

Configure it at **Admin → Plugins → Auth Tools** (`/admin/auth_tools`), or with environment
variables. An environment variable always wins, and the admin page then shows that setting
as locked. Every setting `foo_bar` maps to the variable `AUTH_TOOLS_FOO_BAR`. On the admin
page, each setting shows a description, its default and its environment variable name.
Settings with a fixed set of values, such as `mode` and `header_link_by`, are dropdowns and
list the exact values to use in environment variables.

### Choosing a mode

The `mode` setting (`AUTH_TOOLS_MODE`) picks the active login method:

| Value | Effect |
|---|---|
| `off` (default) | The plugin does nothing, and CTFd's normal login applies. |
| `header` | Trusts the identity header from the reverse proxy. OIDC login is unavailable. |
| `oidc` | Enables OpenID Connect login. The identity header is ignored. |

If you switch away from `header`, sessions that came from the header are logged out on their
next request. An unrecognized value is treated as `off`.

## How accounts are matched

CTFd has no built-in field that can safely hold an external ID:

| Field | Why it isn't used |
|---|---|
| `users.id` | Internal auto-increment value. An external system doesn't know it. |
| `users.oauth_id` | Integer only, so it can't hold string IDs such as an OIDC `sub` or a certificate CN. CTFd's built-in MajorLeagueCyber login uses it, and that login actually matches users by email. |
| `users.name` | Not unique in the database. Users can rename themselves unless `name_changes` is off. |
| `users.email` | Unique, but users can change it, and it's optional. |
| Custom user fields | No uniqueness constraint. Values are stored as JSON, and admins can edit them. |

So the plugin keeps its own mapping table:

```
auth_tools_identities(provider, subject) UNIQUE → users.id  (ON DELETE CASCADE)
```

- `provider` is `"header"` for proxy auth, or the issuer URL for OIDC.
- `subject` is the header value (after the optional regex), or the OIDC `sub` claim.
  Values longer than 255 characters are stored as a SHA-256 hash.
- Comparisons are case-sensitive on every database. On MySQL the columns use the
  `utf8mb4_bin` collation, so two different subjects can't collide.

When an identity has no mapping yet, the plugin:

1. Links it to an existing account, but only if linking is turned on: `header_link_by`
   (`name` or `email`) for header auth, or `oidc_link_by_verified_email` for OIDC. It never
   links to an admin account, or to an account that already has an identity from the same
   provider. For `header_link_by=name`, the ID itself is compared with account names.
2. Otherwise, if auto-create is on, creates a new user. The new user is verified and has no
   password. Its name comes from the identity, with `-2`, `-3` and so on added if the name is
   taken. Account creation respects CTFd's maximum number of users.
3. Otherwise, refuses the login.

Renaming a user or changing their email doesn't break the mapping. Deleting a user removes
their mapping too.

### Linked accounts and passwords

An account linked to an external identity (from either mode) signs in only through that
identity:

- **Password login refused.** CTFd's password login rejects the account with "This account
  does not support password sign-on". This applies even if the
  account somehow has a password, for example one an admin set.
- **No passwords.** Setting a password from the Settings page is refused. Without this rule,
  a user created from their certificate could set a password and then log in without the
  certificate.
- **Other accounts unchanged.** Accounts created through CTFd itself keep password login.
  That includes the admin from the setup wizard and users an admin creates.

## 1. Reverse-proxy header auth

| Setting | Default | Notes |
|---|---|---|
| `header_name` | `X-Auth-ID` | Header carrying the user's identity. |
| `header_email_header` | blank | Optional header to read the new account's email from. |
| `header_trusted_proxies` | `127.0.0.1/32,::1/128` | IPs or CIDRs, comma separated. Checked against the TCP peer address, not `X-Forwarded-For`. This still works if CTFd's `REVERSE_PROXY` is on. |
| `header_subject_regex` | blank | Extracts the ID from the header value. Uses the named group `id`, else group 1. |
| `header_auto_create` | `true` | |
| `header_link_by` | blank | Valid values: blank (don't link), `name`, `email`. Used the first time an ID is seen. Never links to admin accounts. An unknown value is treated as blank. |
| `header_allow_registration` | `false` | Allows CTFd's own `/register` in header mode. |
| `header_hide_logout` | `true` | Hides the Log out link for header sessions, and makes `/logout` do nothing for them. Password sessions keep their Log out link. |
| `header_logout_on_missing` | `true` | Logs out header-based sessions when the header stops arriving. Sessions from a password or OIDC login aren't affected. |

Authentication happens on every request, not on the login page. A hook runs before CTFd
handles any page or API call. The first request that arrives with the header logs the browser
in, creating the account if needed. Later requests only compare the header with the session.
The plugin only touches the database when the identity changes. If a header arrives from an
untrusted peer, the plugin ignores it and logs a warning.

In header mode, `/register` returns 403 by default. The proxy is the only way accounts get
created, which stops someone registering `alice` before the real alice connects with her
certificate. Admin accounts still come from CTFd's setup wizard or the admin panel, and keep
password login. To also hide the "Register" link, set CTFd's **Registration Visibility** to
Private. The plugin's auto-creation doesn't depend on that setting.

If an ID matches the name of an existing account that isn't linked to it, the new account
gets a suffix, for example `admin-2`. It never takes over the existing account.

Example nginx config. `proxy_set_header` replaces any `X-Auth-ID` header the client sent
itself, and **your proxy must do the same**:

```nginx
ssl_client_certificate /etc/nginx/ca.pem;
ssl_verify_client on;

location / {
    proxy_set_header X-Auth-ID $ssl_client_s_dn;   # e.g. "CN=alice,OU=Players,O=CTF"
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_pass http://ctfd:8000;
}
```

```sh
AUTH_TOOLS_HEADER_ENABLED=true
AUTH_TOOLS_HEADER_TRUSTED_PROXIES=172.18.0.0/16   # your proxy's address or Docker network
AUTH_TOOLS_HEADER_SUBJECT_REGEX='(?:^|,)CN=(?P<id>[^,]+)'
```

Things to know:

- Make sure CTFd can only be reached through the proxy. The trusted-proxy list is a second
  line of defense, not a replacement for that.
- **Logging out.** Logging out of a header session would only log the user straight back in
  on the next request. So by default (`header_hide_logout`), the Log out link is hidden for
  those sessions and `/logout` just redirects to the challenges page. The link is hidden by a
  small per-session stylesheet that matches any link to `/logout`, so it works with any theme,
  including themes that draw their menus in the browser. Tested with `core` and
  Challenge Express.
- If an admin bans a user, the header logins for that user get a 403 response.

## 2. OpenID Connect

| Setting | Default | Notes |
|---|---|---|
| `oidc_issuer` | | For example `https://accounts.google.com` or `https://keycloak/realms/ctf`. The plugin reads endpoints from `/.well-known/openid-configuration`. |
| `oidc_client_id` / `oidc_client_secret` | | |
| `oidc_scopes` | `openid profile email` | |
| `oidc_token_auth_method` | `client_secret_basic` | Valid values: `client_secret_basic`, `client_secret_post`. An unknown value is treated as `client_secret_basic`. |
| `oidc_username_claim` | `preferred_username` | If that claim is missing, falls back to `name`, then `email`, then `sub`. |
| `oidc_button_text` | `Log in with SSO` | Label of the SSO button. |
| `oidc_password_toggle_text` | `Sign in with username / email` | Label of the toggle that shows CTFd's password form. |
| `oidc_divider_text` | `or` | Text in the divider between the SSO button and the toggle. |
| `oidc_redirect_uri` | derived | Set this if CTFd's external URL detection gets it wrong. |
| `oidc_auto_create` | `true` | |
| `oidc_link_by_verified_email` | `false` | Links to an existing account with the same email, only if the IdP sends `email_verified: true`. |
| `oidc_allow_http` | `false` | For local testing only. |

The redirect URI to register with your provider is `https://<ctfd>/auth_tools/oidc/callback`.
The settings page shows the exact URI.

Security behavior:

- The flow uses `state`, `nonce` and PKCE (S256).
- The plugin checks the ID token's `iss`, `aud`, `azp`, `exp` and `nonce`.
- It doesn't check the ID token's signature. The token comes straight from the token
  endpoint over TLS with client authentication, and OIDC Core §3.1.3.7(6) allows TLS server
  validation in place of a signature check in that case. For the same reason, the plugin
  requires https for all IdP endpoints.
- New accounts only store the email if the IdP marks it as verified. CTFd sends password
  resets to that address.
- The `?next=` redirect only accepts same-site URLs.

Login page in OIDC mode:

- **Layout.** The SSO button comes first, then an "or" divider, then a full-width "Sign in
  with username / email" toggle with a chevron. The toggle reveals CTFd's own form, so admins
  can still use a password. When the form is open, the SSO button switches to an outline
  style, so the form's submit button is the main action.
- **Opening the form.** The form opens automatically after a failed password attempt, so
  CTFd's error appears next to it. Linking to `/login#password` also opens it.
- **Register page.** The register page shows the SSO button above the registration form,
  which stays visible.
- **Accessibility.** The toggle is a real button with `aria-expanded`. Opening the form moves
  focus to its first field, and the reveal animation is off for users who prefer reduced
  motion.

### Theme support

A small script adds the buttons, so the plugin doesn't override any theme templates. It works
with any theme whose login page has a normal `<form>` with a `password` field. That includes
themes that draw the page in the browser with Svelte, React and similar: the script waits for
the form to appear and never moves the theme's own elements. It only adds elements next to
the form and hides the form with a class.

Tested with CTFd's `core` theme, in light and dark mode, and with
[Challenge Express](https://github.com/featherbear/ctfd-theme-challenge-express), which is a
Svelte theme.

The buttons use Bootstrap classes (`btn`, `btn-primary`, `btn-outline-secondary`), so they
pick up the theme's button styles. To restyle them, themes can target `#auth-tools-sso`,
`#auth-tools-divider`, `#auth-tools-password-toggle` and `.auth-tools-open`.

The plugin can't change a theme's own wording. For example, Challenge Express still says
"Enter your user name and password to continue." above the SSO button.

## Admin API: linked accounts

`GET /api/v1/auth_tools/identities` lists every CTFd account linked to a reverse-proxy or
OpenID identity. Normal CTFd accounts, such as the setup admin, aren't included. It's
admin-only: anyone else gets `403`.

| Query parameter | Effect |
|---|---|
| `via=header` / `via=oidc` | Only reverse-proxy or only OpenID accounts. Any other value gives `400`. |
| `user_id=<int>` | One CTFd user. |
| `subject=<str>` | Exact external ID: the header value after the regex, or the OIDC `sub`. |

From a script, use a CTFd API token (Settings → Access Tokens) from an admin account. Like
CTFd's own API, token requests need the JSON content type:

```sh
curl -H "Authorization: Token ctfd_..." -H "Content-Type: application/json" \
     "https://ctfd.example.com/api/v1/auth_tools/identities?via=header"
```

```json
{
  "success": true,
  "data": [
    {
      "id": 1, "via": "header", "provider": "header", "subject": "alice",
      "user_id": 2, "name": "alice", "email": "alice@example.com",
      "type": "user", "banned": false, "hidden": false,
      "created": "2026-11-10T14:25:50.128300Z"
    }
  ],
  "meta": {"count": 1}
}
```

For OpenID accounts, `provider` is the issuer URL. The endpoint returns everything in one
response, without pagination.

## Limitations and possible follow-ups

- Password login stays available. Users created through SSO or the header have no password,
  but CTFd lets them set one from Settings.
- In teams mode, new users have no team, and CTFd asks them to create or join one as usual.
  The plugin doesn't map IdP groups to teams.
- CTFd's "registration visibility" setting doesn't control auto-creation. The `*_auto_create`
  settings do.

## Dev stack

`dev/` contains a Docker Compose stack that exercises both modes end to end. It starts in
`oidc` mode. To test mTLS, restart it in `header` mode:

```sh
AUTH_TOOLS_MODE=header docker compose up -d   # back to OIDC: docker compose up -d
```

| URL | What it is |
|---|---|
| `https://ctfd.localhost:8443` | CTFd. In `oidc` mode it shows the "Log in with Dex" button. Caddy strips any `X-Auth-ID` header the client sends. |
| `https://mtls.ctfd.localhost:8443` | The same CTFd behind mTLS. Caddy requires a client cert and passes its subject DN as `X-Auth-ID` and its email as `X-Auth-Email`. Logs you in only in `header` mode. |
| `https://dex.localhost:8443` | [Dex](https://dexidp.io), a standalone OpenID Connect provider with users defined in `dev/dex.yaml`. |

```sh
cd dev
./gen-certs.sh          # dev CA, server cert, client certs for alice and bob
docker compose up -d    # ctfd-setup runs CTFd's setup wizard automatically
```

Logins:

- **CTFd admin:** `admin` / `password`.
- **Dex:** `carol@example.com` or `dave@example.com`, password `password`.
- **mTLS:** import `dev/certs/alice.p12` or `bob.p12` into your browser or keychain. The
  PKCS#12 password is `changeit`.

Notes:

- To avoid certificate warnings, trust `dev/certs/ca.crt`. On macOS:
  `sudo security add-trusted-cert -d -k /Library/Keychains/System.keychain dev/certs/ca.crt`.
  Remove it again when you're done.
- Chrome and Firefox resolve `*.localhost` to 127.0.0.1 automatically. Other clients may need
  `/etc/hosts` entries.
- CTFd is not published to the host. Inside the network, Caddy has the fixed IP 172.30.0.10,
  which is the only trusted proxy.
- The plugin directory is mounted read-only. After changing code, run
  `docker compose restart ctfd`.
- To reset everything, run `docker compose down -v`.

Testing with curl:

```sh
cd dev/certs
curl --cacert ca.crt --cert alice.crt --key alice.key https://mtls.ctfd.localhost:8443/api/v1/users/me
```

## Tests

The tests use CTFd's own test helpers inside the official image:

```sh
docker run --rm --user root --entrypoint sh \
  -v "$PWD/auth_tools:/opt/CTFd/CTFd/plugins/auth_tools:ro" \
  -v "$PWD/tests/test_auth_tools.py:/opt/CTFd/tests/test_auth_tools_plugin.py:ro" \
  -w /opt/CTFd ctfd/ctfd:3.8.9 \
  -c 'pip install -q pytest && python -m pytest -q tests/test_auth_tools_plugin.py'
```

To run them against MySQL or MariaDB, add `-e TESTING_DATABASE_URL=mysql+pymysql://...`.
