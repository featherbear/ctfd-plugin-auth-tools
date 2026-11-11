# ctfd-plugin--auth-tools

A CTFd plugin that adds more methods to log in.  
Accounts created through this plugin are external accounts: they're independent, and never linked to existing password-backed accounts.

Available methods:

- **Upstream header.** A trusted reverse proxy authenticates the user and passes their identity to CTFd in a header (`X-Auth-ID` by default). The proxy can use any method, for example client certificates (mTLS) or an SSO gateway such as Authelia or oauth2-proxy. Users are logged in automatically, and their account is created the first time they log in.
- **OpenID Connect.** Users log in through an identity provider such as Keycloak, Dex or Google. It becomes the primary method on the login page, but still shows the username/password method for password-backed accounts.

Built and tested against CTFd 3.8.9

## Quick start

```sh
cp -r auth_tools /path/to/CTFd/CTFd/plugins/auth_tools
```

Restart CTFd, then choose a login method at **Admin -> Auth Tools**, or with the environment variables: `AUTH_TOOLS_MODE=header` or `AUTH_TOOLS_MODE=oidc`.

## Documentation

- [Installation](docs/installation.md): requirements, installing, upgrading and uninstalling.
- [Configuration](docs/configuration.md): modes, every setting, proxy examples and provider
  setup.
- [How accounts are matched](docs/accounts.md): the identity table, first-login behavior and
  password rules.
- [Admin API](docs/api.md): listing external accounts.
- [Contributing](docs/contributing.md): project layout, the Docker dev stack and tests.

