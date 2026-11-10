# Contributing

## Project layout

```
auth_tools/                 the plugin (copied to CTFd/plugins/auth_tools)
  __init__.py               load(): registers routes, hooks, site.js and session.css
  config.py                 every setting: default, kind, description, valid values
  header_auth.py            header mode: per-request hook, trusted-proxy check
  oidc.py                   OIDC mode: login and callback routes
  provisioning.py           find, link or create the user for an identity
  policy.py                 password-login, password-change, /register and /logout rules
  api.py                    admin API: GET /api/v1/auth_tools/identities
  models.py                 auth_tools_identities table
  migrations/               Alembic migrations, used on MySQL/MariaDB
  assets/site.js            login page SSO button; locks Settings fields for linked accounts
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

The tests use CTFd's own test helpers inside the official image, so you don't need a local
CTFd checkout:

```sh
docker run --rm --user root --entrypoint sh \
  -v "$PWD/auth_tools:/opt/CTFd/CTFd/plugins/auth_tools:ro" \
  -v "$PWD/tests/test_auth_tools.py:/opt/CTFd/tests/test_auth_tools_plugin.py:ro" \
  -w /opt/CTFd ctfd/ctfd:3.8.9 \
  -c 'pip install -q pytest && python -m pytest -q tests/test_auth_tools_plugin.py'
```

By default they use an in-memory SQLite database. To run them against MySQL or MariaDB, which
also exercises the Alembic migration, add `-e TESTING_DATABASE_URL=mysql+pymysql://...`.

Notes for writing tests:

- **Proxy address.** Header-mode requests need `environ_base={"REMOTE_ADDR": "127.0.0.1"}`
  to come from a trusted proxy. Use the `PROXY` constant.
- **Settings.** Set them with `monkeypatch.setenv("AUTH_TOOLS_...")`. The `header_env` and
  `idp` fixtures switch modes.
- **OIDC.** The `idp` fixture is a fake provider. Set `idp.claims` to change the ID token.
- **CSRF.** CTFd's test client adds the `CSRF-Token` header to JSON requests itself. Don't
  add your own, or the request will be rejected.

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
