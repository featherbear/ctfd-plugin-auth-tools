# Admin API

## List external accounts

```
GET /api/v1/auth_tools/identities
```

Lists every external account: accounts created by upstream header or OpenID Connect login.
Password-backed accounts,
such as the setup admin, aren't included.

It's admin-only. Anyone else, including users with their own API token, gets `403`.

### Query parameters

All are optional, and they can be combined.

| Parameter | Effect |
|---|---|
| `via=header` / `via=oidc` | Only reverse-proxy or only OpenID accounts. Any other value gives `400`. |
| `user_id=<int>` | One CTFd user. A non-integer gives `400`. |
| `subject=<str>` | Exact external ID: the header value after the regex, or the OIDC `sub`. |

### Authentication

From a browser, a logged-in admin session works.

From a script, create an API token on an admin account (**Settings → Access Tokens**). Like
CTFd's own API, token requests must send the JSON content type:

```sh
curl -H "Authorization: Token ctfd_..." -H "Content-Type: application/json" \
     "https://ctfd.example.com/api/v1/auth_tools/identities?via=header"
```

### Response

```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "via": "header",
      "provider": "header",
      "subject": "alice",
      "user_id": 2,
      "name": "alice",
      "email": "alice@example.com",
      "type": "user",
      "banned": false,
      "hidden": false,
      "created": "2026-11-10T14:25:50.128300Z"
    }
  ],
  "meta": {"count": 1}
}
```

| Field | Meaning |
|---|---|
| `id` | ID of the identity mapping. |
| `via` | `header` or `oidc`. |
| `provider` | `header`, or the issuer URL for OpenID accounts. |
| `subject` | The external ID. |
| `user_id`, `name`, `email`, `type`, `banned`, `hidden` | The linked CTFd user. |
| `created` | When the CTFd user was created (UTC). |

Errors look like `{"success": false, "errors": ["..."]}`.

The endpoint returns everything in one response, without pagination.
