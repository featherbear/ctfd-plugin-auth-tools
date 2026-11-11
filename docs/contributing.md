# Contributing

## Project layout

```
auth_tools/                 the plugin (copied to CTFd/plugins/auth_tools)
  __init__.py               load(): registers routes, hooks, site.js and session.css
  config.py                 every setting: default, kind, description, valid values
  header_auth.py            upstream header mode: per-request hook, trusted-proxy check
  oidc.py                   OpenID Connect (OIDC) mode: login and callback routes
  provisioning.py           find, link or create the user for an identity
  policy.py                 password-login, password-change, /register and /logout rules
  api.py                    admin API: GET /api/v1/auth_tools/identities
  models.py                 auth_tools_identities table
  migrations/               Alembic migrations, used on MySQL/MariaDB
  assets/site.js            login page SSO button; locks Settings fields for external accounts
  assets/admin.js           "External" badges and Edit User changes on admin user pages
  templates/settings.html   admin settings page
tests/test_auth_tools.py    pytest suite, run inside the CTFd image
dev/                        Docker Compose stack: CTFd, Caddy (mTLS), Dex (OIDC)
docs/                       this documentation
```

## Dev stack

`dev/` runs both login modes end to end:

| URL | What it is |
|---|---|
| `https://ctfd.localhost:8443` | CTFd. In `oidc` mode it shows the "Log in with Dex" button. Caddy strips any `X-Auth-ID` header the client sends. |
| `https://mtls.ctfd.localhost:8443` | The same CTFd behind mTLS. Caddy requires a client certificate and passes its subject as `X-Auth-ID` and its email as `X-Auth-Email`. Logs you in only in `header` mode. |
| `https://dex.localhost:8443` | [Dex](https://dexidp.io), a standalone OpenID Connect provider with users defined in `dev/dex.yaml`. |

Start it:

```sh
cd dev
./gen-certs.sh          # dev CA, server cert, client certs for alice and bob
docker compose up -d    # ctfd-setup runs CTFd's setup wizard automatically
```

It starts in `oidc` mode. To test mTLS, restart it in `header` mode:

```sh
AUTH_TOOLS_MODE=header docker compose up -d   # back to OIDC: docker compose up -d
```

The mode only applies to the command you set it on, so a plain `docker compose up -d` later
switches back to OIDC.

Logins:

- **CTFd admin:** `admin` / `password`.
- **Dex:** `carol@example.com` or `dave@example.com`, password `password`.
- **mTLS:** import `dev/certs/alice.p12` or `bob.p12` into your browser or keychain. The
  PKCS#12 password is `changeit`. `./gen-certs.sh carol` makes another one.

### Browser setup

- **Certificate warnings.** To avoid them, trust the dev CA. On macOS:
  ```sh
  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain dev/certs/ca.crt
  ```
  Remove it again when you're done.
- **Client certificates.** On macOS:
  `security import dev/certs/alice.p12 -k ~/Library/Keychains/login.keychain-db -P changeit`.
  Chrome and Safari use the Keychain. Firefox has its own store: Settings → Privacy &
  Security → Certificates → View Certificates → Your Certificates → Import.
- **Switching certificates.** Chrome remembers the certificate you picked until it restarts.
  Quit it fully, or use a separate profile.
- **`*.localhost` names.** Chrome and Firefox resolve them to 127.0.0.1 automatically. Other
  clients may need `/etc/hosts` entries.

### Notes

- CTFd isn't published to the host. Inside the Docker network, Caddy has the fixed IP
  172.30.0.10, which is the only trusted proxy.
- The plugin directory is mounted read-only. After changing Python code or templates, run
  `docker compose restart ctfd`. `assets/site.js` is read again on every request, so
  reloading the page is enough.
- `dev/certs/` is in `.gitignore`. Never commit it.
- To reset everything, run `docker compose down -v`.

Testing with curl:

```sh
cd dev/certs
curl --cacert ca.crt --cert alice.crt --key alice.key https://mtls.ctfd.localhost:8443/api/v1/users/me
```

## Tests

All tests are in `tests/test_auth_tools.py`. They run inside the official CTFd image using
CTFd's own test helpers, so you don't need a local CTFd checkout or Python environment.

### Running them

From the repository root:

```sh
docker run --rm --user root --entrypoint sh \
  -v "$PWD/auth_tools:/opt/CTFd/CTFd/plugins/auth_tools:ro" \
  -v "$PWD/tests/test_auth_tools.py:/opt/CTFd/tests/test_auth_tools_plugin.py:ro" \
  -w /opt/CTFd ctfd/ctfd:3.8.9 \
  -c 'pip install -q pytest && python -m pytest -q tests/test_auth_tools_plugin.py'
```

This uses an in-memory SQLite database and takes about 20 seconds.

To run only some tests, add pytest's `-k` option. For example, replace the last line with:

```sh
  -c 'pip install -q pytest && python -m pytest -q tests/test_auth_tools_plugin.py -k "oidc and email"'
```

### Running them against MariaDB

On SQLite the plugin creates its table directly. On MySQL and MariaDB it runs its Alembic
migration, and string comparisons behave differently (see the case-sensitivity test). Run
the suite against MariaDB before merging changes to the model, the migration or anything
that queries the database. It takes about 45 seconds:

```sh
docker network create auth-tools-test
docker run -d --rm --name auth-tools-test-db --network auth-tools-test \
  -e MARIADB_ROOT_PASSWORD=pw mariadb:10.11
until docker exec auth-tools-test-db healthcheck.sh --connect --innodb_initialized; do sleep 2; done

docker run --rm --user root --entrypoint sh --network auth-tools-test \
  -e TESTING_DATABASE_URL=mysql+pymysql://root:pw@auth-tools-test-db/ctfd \
  -v "$PWD/auth_tools:/opt/CTFd/CTFd/plugins/auth_tools:ro" \
  -v "$PWD/tests/test_auth_tools.py:/opt/CTFd/tests/test_auth_tools_plugin.py:ro" \
  -w /opt/CTFd ctfd/ctfd:3.8.9 \
  -c 'pip install -q pytest && python -m pytest -q tests/test_auth_tools_plugin.py'

# Clean up, even if the tests failed
docker rm -f auth-tools-test-db
docker network rm auth-tools-test
```

Each test creates its own database with a random name, so runs don't interfere with each
other.

### Writing tests

Every test gets a fresh CTFd from the `app` fixture, already set up, with an admin account
`admin` / `password`. All `AUTH_TOOLS_*` environment variables are cleared first, so the
plugin starts in `off` mode.

Fixtures:

| Fixture | Gives you |
|---|---|
| `app` | A fresh CTFd with the plugin loaded. |
| `header_env` | Switches to `header` mode. |
| `idp` | Switches to `oidc` mode with a fake identity provider. Set `idp.claims` to change what the ID token contains, for example `{"sub": "u1", "email": "a@example.com", "email_verified": True}`. |
| `linked` | Two upstream header users (alice, bob), one OIDC user (frank) and one password-backed user (plain). Used by the admin API tests. |
| `mail` | Makes CTFd think it can send email, and records password-reset emails in a list instead of sending them. |

Helpers and constants:

| Name | Use |
|---|---|
| `PROXY` / `OUTSIDE` | `environ_base` values for a request from a trusted proxy (127.0.0.1) or from an untrusted address. |
| `ALICE` | Keyword arguments for a header-mode request as alice from the trusted proxy: `c.get("/", **ALICE)`. |
| `run_flow(c, idp)` | Runs the full OIDC login with client `c`. Returns the callback response. |
| `_oidc_user(app, idp)` | Creates an OIDC user and returns their user ID. |
| `_password_login(app, name, password)` | Tries CTFd's password login. Returns the response and the logged-in user ID, or `None`. |
| `_set_password_via_api(c, password)` | Tries to set a password from the user's own Settings, through the API. |
| `identities(app)` | All rows of the identity table, as `(provider, subject, user_id)`. |

Things that commonly trip people up:

- **Settings.** Set them with `monkeypatch.setenv("AUTH_TOOLS_...")`. They're read on every
  request, so you can change them partway through a test.
- **Upstream header mode needs the proxy address and the header on every request.** A request
  without the header is treated as the header disappearing, which logs out a header session
  (`header_logout_on_missing`). Pass `**ALICE`, or `headers=` plus `environ_base=PROXY`, each
  time.
- **CTFd's own checks run before the plugin's header login.** On the very first request, the
  user isn't logged in yet when CTFd's hooks run. Behavior that depends on CTFd seeing a
  logged-in user, such as the forced password-change redirect, only shows up from the second
  request on.
- **CSRF.** CTFd's test client adds the `CSRF-Token` header to JSON requests itself. Don't
  add your own: the request would carry two tokens and be rejected with a 403. Form posts
  need the session's `nonce` in the form data, as `_post_form` and `_password_login` show.
- **Hidden users don't appear in CTFd's user list API.** The setup admin is hidden, so look
  users up through the database (`Users.query`) rather than `/api/v1/users`.
- **Prove the test can fail.** For security behavior, temporarily remove your fix and check
  that the new test goes red.

### Browser checks

The test suite doesn't run a browser. Changes to the login page, Settings page or admin
pages (`assets/*.js`) also need checking by hand on the [dev stack](#dev-stack). See
[Making changes](#making-changes) for which themes and modes to cover.

## Making changes

- **New settings** go in `config.py`, with a description. A test fails if a setting has no
  description. Settings with a fixed set of values should be `choice` settings, with the
  safe option first, because unknown values fall back to it.
- **Database changes** need a new Alembic migration in `auth_tools/migrations/`, as well as
  the model change. Test them against MariaDB.
- **Security-sensitive behavior** (trust checks, account linking, password rules) needs a
  test that fails without the change. Temporarily remove your fix and check that the test
  goes red.
- **Login and Settings page changes** should be checked in a browser with the `core` theme in light and
  dark mode, and with a client-rendered theme such as
  [Challenge Express](https://github.com/featherbear/ctfd-theme-challenge-express).
- **Docs.** Update the relevant page in `docs/`.

## Pull requests

1. Branch from `main`.
2. Make sure the test suite passes.
3. Open a pull request describing what changed and how you tested it.
