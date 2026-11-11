# Configuration

- [How settings work](#how-settings-work)
- [Choosing a mode](#choosing-a-mode)
- [Upstream header mode](#upstream-header-mode)
- [OIDC mode (OpenID Connect)](#oidc-mode-openid-connect)
- [Limitations](#limitations)

## How settings work

You can set each setting in two places:

1. **Environment variable.** A setting `foo_bar` maps to the variable `AUTH_TOOLS_FOO_BAR`.
   An environment variable always wins, and the admin page shows that setting as locked.
2. **Admin page.** Go to **Admin → Auth Tools** (`/admin/auth_tools`).

If neither is set, the default applies.

On the admin page, each setting shows a description, its default and its environment
variable name. Settings with a fixed set of values, such as `mode` and
`oidc_token_auth_method`, are dropdowns and list the exact values to use in environment
variables. An unknown value falls back to the safe default.

## Choosing a mode

The plugin supports two login methods, and only one can be active at a time. `mode`
(`AUTH_TOOLS_MODE`) picks it:

| Value | Effect |
|---|---|
| `off` (default) | The plugin does nothing, and CTFd's normal login applies. |
| `header` | Upstream header: trusts the identity header from the reverse proxy. OIDC login is unavailable. |
| `oidc` | OpenID Connect (OIDC) login. The identity header is ignored. |

If you switch away from `header`, sessions that came from the header are logged out on their
next request. An unrecognized value is treated as `off`.

In both modes, the accounts the plugin creates are external accounts, and they can't use password login. Accounts
created through CTFd itself, such as the setup admin, keep it. See
[External accounts and passwords](accounts.md#external-accounts-and-passwords).

## Upstream header mode

A reverse proxy in front of CTFd authenticates the user and passes their identity to CTFd in a
header. The plugin logs the request in as the matching CTFd user, and creates the account the
first time it sees that identity.

The plugin doesn't care how the proxy authenticates users. For example, it can:
- verify client certificates (mTLS);
- use an SSO gateway such as Authelia, Authentik or oauth2-proxy;
- use an access proxy such as Cloudflare Access or Tailscale.

What matters is that the proxy is the only way to reach CTFd, and that it controls the header.

### Settings

| Setting | Default | Notes |
|---|---|---|
| `header_name` | `X-Auth-ID` | Header carrying the user's identity. |
| `header_email_header` | blank | Optional header with the user's email address. Only used when an account is created. |
| `header_trusted_proxies` | `127.0.0.1/32,::1/128` | IPs or CIDRs, comma separated, allowed to send the header. Checked against the TCP peer address, not `X-Forwarded-For`, so it still works if CTFd's `REVERSE_PROXY` is on. |
| `header_subject_regex` | blank | Extracts the ID from the header value. Uses the named group `id`, else group 1, else the whole match. |
| `header_auto_create` | `true` | Creates an account the first time an unknown ID arrives. When off, unknown IDs get a 403. |
| `header_allow_registration` | `false` | Allows CTFd's own `/register` page in upstream header mode. |
| `header_hide_logout` | `true` | Hides the Log out link for header sessions, and makes `/logout` do nothing for them. |
| `header_logout_on_missing` | `true` | Logs out header sessions when a request arrives without the header. Password sessions aren't affected. |

### How it behaves

- **Every request.** Authentication doesn't happen on the login page. A hook runs before CTFd
  handles any page or API call, so the first request that arrives with the header logs the
  browser in. Later requests only compare the header with the session. The plugin only
  touches the database when the identity changes.
- **The header wins.** If a request arrives with a trusted header for a different user than
  the session, the session switches to that user. That includes sessions from a password
  login.
- **Separate accounts.** Each ID gets its own new account. It's never attached to an existing
  account with the same name or email, because users can change both. If the name is taken,
  the new account gets a suffix such as `alice-2`.
- **Untrusted senders are ignored.** A header from an address outside
  `header_trusted_proxies` is ignored, and the plugin logs a warning.
- **Registration is closed.** `/register` returns 403 by default, so the proxy is the only way
  accounts get created. This stops someone registering `alice` before the real alice first
  logs in. Admin accounts still come from CTFd's setup wizard or the
  admin panel. To also hide the "Register" link, set CTFd's **Registration Visibility** to
  Private.
- **No Log out link.** Logging out of a header session would only log the user straight back
  in on the next request. So the Log out link is hidden for those sessions, and `/logout`
  redirects to the challenges page. A small per-session stylesheet hides any link to
  `/logout`, so this works with any theme.
- **Bans.** If an admin bans a user, that user's header logins get a 403 response.

### Proxy setup

Your proxy must **set** the identity header on every request it forwards to CTFd, replacing
any copy the client sent. On routes that don't authenticate the client, it must **remove**
the header.

#### Example: client certificates (mTLS) with Caddy

This is what the [dev stack](contributing.md#dev-stack) uses.

```caddy
# Site with client certificates
mtls.ctf.example.com {
	tls {
		client_auth {
			mode require_and_verify
			trust_pool file /certs/ca.crt
		}
	}
	reverse_proxy ctfd:8000 {
		header_up -X_Auth_ID
		header_up X-Auth-ID {http.request.tls.client.subject}
		header_up X-Auth-Email {http.request.tls.client.san.emails.0}
	}
}

# Any other site that reaches CTFd
ctf.example.com {
	reverse_proxy ctfd:8000 {
		header_up -X-Auth-ID
		header_up -X_Auth_ID
		header_up -X-Auth-Email
	}
}
```

#### Example: client certificates (mTLS) with nginx

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

CTFd settings for either mTLS example:

```sh
AUTH_TOOLS_MODE=header
AUTH_TOOLS_HEADER_TRUSTED_PROXIES=172.18.0.10/32            # your proxy's address
AUTH_TOOLS_HEADER_SUBJECT_REGEX='(?:^|,)CN=(?P<id>[^,]+)'   # use the certificate CN as the ID
AUTH_TOOLS_HEADER_EMAIL_HEADER=X-Auth-Email                 # optional
```

#### Example: SSO gateway (Authelia) with Caddy

Caddy's `forward_auth` asks Authelia whether the user is logged in, then copies Authelia's
`Remote-User` and `Remote-Email` headers onto the request.

```caddy
ctf.example.com {
	# A route runs its directives in the order written. Strip any copies the
	# client sent *before* forward_auth sets the real values. Outside a route,
	# Caddy would run request_header after forward_auth and strip those too.
	route {
		request_header -Remote-User
		request_header -Remote_User
		request_header -Remote-Email
		request_header -Remote_Email
		forward_auth authelia:9091 {
			uri /api/authz/forward-auth
			copy_headers Remote-User Remote-Email
		}
		reverse_proxy ctfd:8000
	}
}
```

CTFd settings:

```sh
AUTH_TOOLS_MODE=header
AUTH_TOOLS_HEADER_NAME=Remote-User                  # Authelia's username, used as the ID
AUTH_TOOLS_HEADER_EMAIL_HEADER=Remote-Email         # optional
AUTH_TOOLS_HEADER_TRUSTED_PROXIES=172.18.0.10/32    # Caddy's address
```

The same pattern works for other gateways. Use whichever header carries a stable,
unique username, and don't use a display name.

### Security checklist

- **Isolate CTFd.** It should only be reachable through the proxy. Don't publish its port.
  The trusted-proxy list is a second line of defense, not a replacement for this.
- **Cover every route.** Every site block, catch-all site and extra route that forwards to
  CTFd needs the set or remove rule.
- **Strip underscore variants too.** Python servers treat `X_Auth_ID` the same as
  `X-Auth-ID`, but proxies treat them as different headers. Gunicorn 22 and later, which
  CTFd 3.8.9 ships, drop underscore headers by default. Stripping them in the proxy as well
  removes that dependency. Never run CTFd's Flask development server behind the proxy.
- **Test it.** Send `X-Auth-ID: CN=canary` and `X_Auth_ID: CN=canary` to every hostname and
  path, then confirm that no account called `canary` appears.

## OIDC mode (OpenID Connect)

Users log in through an OpenID Connect provider, such as Keycloak, Dex, Authentik, Google or
Microsoft Entra ID. The plugin uses the authorization code flow with PKCE.

### Provider setup

Register CTFd as a confidential client (it has a client secret) with:

- **Redirect URI:** `https://<your-ctfd>/auth_tools/oidc/callback`. The settings page shows
  the exact URI.
- **Scopes:** `openid profile email`.

### Settings

| Setting | Default | Notes |
|---|---|---|
| `oidc_issuer` | blank | For example `https://accounts.google.com` or `https://keycloak.example.com/realms/ctf`. The plugin reads endpoints from `/.well-known/openid-configuration`. |
| `oidc_client_id` | blank | Client ID registered with the provider. |
| `oidc_client_secret` | blank | Client secret registered with the provider. |
| `oidc_scopes` | `openid profile email` | Must include `openid`. |
| `oidc_token_auth_method` | `client_secret_basic` | Valid values: `client_secret_basic`, `client_secret_post`. |
| `oidc_username_claim` | `preferred_username` | Claim used as the name of new accounts. Falls back to `name`, then `email`, then `sub`. |
| `oidc_button_text` | `Log in with SSO` | Label of the SSO button. |
| `oidc_password_toggle_text` | `Log in with username / email` | Label of the toggle that reveals CTFd's password form. |
| `oidc_divider_text` | `or` | Text in the divider between the SSO button and the toggle. |
| `oidc_redirect_uri` | derived | Set this if CTFd builds the wrong external URL, for example because `REVERSE_PROXY` isn't set. |
| `oidc_auto_create` | `true` | Creates an account the first time an unknown user logs in. When off, they're refused. |
| `oidc_allow_http` | `false` | Allows plain-http provider URLs. For local testing only. |

Example:

```sh
AUTH_TOOLS_MODE=oidc
AUTH_TOOLS_OIDC_ISSUER=https://keycloak.example.com/realms/ctf
AUTH_TOOLS_OIDC_CLIENT_ID=ctfd
AUTH_TOOLS_OIDC_CLIENT_SECRET=...
AUTH_TOOLS_OIDC_BUTTON_TEXT="Log in with Keycloak"
```

### Login page

- **Layout.** The SSO button comes first, then an "or" divider, then a "Log in with username
  / email" toggle. The toggle reveals CTFd's own form, so admins can still use a password.
  When the form is open, the SSO button switches to an outline style, so the form's submit
  button is the main action.
- **Opening the form.** The form opens automatically after a failed password attempt, so
  CTFd's error appears next to it. Linking to `/login#password` also opens it.
- **Register page.** The SSO button appears above the registration form, which stays
  visible.
- **Accessibility.** The toggle is a real button with `aria-expanded`. Opening the form moves
  focus to its first field, and there's no animation for users who prefer reduced motion.

### Theme support

A small script adds the buttons, so the plugin doesn't override any theme templates. It works
with any theme whose login page has a normal `<form>` with a `password` field. That includes
themes that draw the page in the browser with Svelte, React and similar: the script waits for
the form to appear and never moves the theme's own elements.

Tested with CTFd's `core` theme, in light and dark mode, and with
[Challenge Express](https://github.com/featherbear/ctfd-theme-challenge-express), a Svelte
theme.

The buttons use Bootstrap classes (`btn`, `btn-primary`, `btn-outline-secondary`), so they
pick up the theme's button styles. To restyle them, a theme can target `#auth-tools-sso`,
`#auth-tools-divider`, `#auth-tools-password-toggle` and `.auth-tools-open`.

The plugin can't change a theme's own wording. For example, Challenge Express still says
"Enter your user name and password to continue." above the SSO button.

### Security behavior

- The flow uses `state`, `nonce` and PKCE (S256).
- The plugin checks the ID token's `iss`, `aud`, `azp`, `exp` and `nonce`.
- It doesn't check the ID token's signature. The token comes straight from the token
  endpoint over TLS with client authentication, and OIDC Core §3.1.3.7(6) allows TLS server
  validation in place of a signature check in that case. For the same reason, the plugin
  requires https for all provider endpoints.
- **Separate accounts.** OIDC users always get their own account. They're never linked to an
  existing CTFd account, even one with the same email, because users can change their CTFd
  email. If the email is already used by another account, the new account is created
  without one.
- New accounts only store the email if the provider marks it as verified.
- The `?next=` redirect only accepts same-site URLs.
- **Sessions are independent of the provider.** After login, the user has an ordinary CTFd
  session. Logging out of the provider, or disabling the user there, doesn't log them out of
  CTFd. The session lasts for CTFd's `PERMANENT_SESSION_LIFETIME`, which is 7 days by
  default. Banning the user in CTFd ends it on their next request.

## Limitations

- **Teams mode.** New users have no team, and CTFd asks them to create or join one as usual.
  The plugin doesn't map provider groups to teams.
- **Registration visibility.** CTFd's "Registration Visibility" setting doesn't control
  auto-creation. The `*_auto_create` settings do.
- **Admin sign-in.** There's no way to deliberately link an admin account to a proxy or OIDC
  identity, so admins log in with a password.
