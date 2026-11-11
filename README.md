# ctfd-auth-tools

A CTFd plugin that adds two ways to log in. Only one can be active at a time:

- **Reverse-proxy header.** A trusted reverse proxy authenticates the user and passes their
  identity to CTFd in a header (`X-Auth-ID` by default). The proxy can use any method, for
  example client certificates (mTLS) or an SSO gateway such as Authelia or oauth2-proxy.
  Users are logged in automatically, and their account is created the first time they sign
  in.
- **OpenID Connect.** Users log in through an identity provider such as Keycloak, Dex or
  Google. The login page shows the SSO button first, with CTFd's username/password form
  behind a toggle.

Accounts created through either method sign in only through it. They can't log in with a
password or get one, and they're never linked to existing accounts. Normal CTFd
accounts, such as the admin, are unaffected.

Built and tested against CTFd 3.8.9. No dependencies beyond what CTFd already ships.

## Quick start

```sh
cp -r auth_tools /path/to/CTFd/CTFd/plugins/auth_tools
```

Restart CTFd, then choose a login method at **Admin → Auth Tools**, or with
`AUTH_TOOLS_MODE=header` or `AUTH_TOOLS_MODE=oidc`.

## Documentation

- [Installation](docs/installation.md): requirements, installing, upgrading and uninstalling.
- [Configuration](docs/configuration.md): modes, every setting, proxy examples and provider
  setup.
- [How accounts are matched](docs/accounts.md): the identity table, first-login behavior and
  password rules.
- [Admin API](docs/api.md): listing accounts linked to a proxy or OpenID identity.
- [Contributing](docs/contributing.md): project layout, the Docker dev stack and tests.
