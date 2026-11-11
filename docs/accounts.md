# How accounts are matched

## Why the plugin has its own table

CTFd has no built-in field that can safely hold an external ID:

| Field | Why it isn't used |
|---|---|
| `users.id` | Internal auto-increment value. An external system doesn't know it. |
| `users.oauth_id` | Integer only, so it can't hold string IDs such as an OIDC `sub` or a certificate CN. CTFd's built-in MajorLeagueCyber login uses it, and users can see it in the API. |
| `users.name` | Not unique in the database. Users can rename themselves unless `name_changes` is off. |
| `users.email` | Unique, but users can change it, and it's optional. |
| `users.secret` | Hidden from users and unused by CTFd, but not unique or indexed, and a future CTFd version could start using it. |
| Custom user fields | No uniqueness constraint. Even "non-editable" fields can be filled in by the user at registration, or through the API while empty. |

So the plugin keeps its own mapping table, which users can't see or change:

```
auth_tools_identities(provider, subject) UNIQUE → users.id  (ON DELETE CASCADE)
```

- `provider` is `"header"` for proxy auth, or the issuer URL for OIDC.
- `subject` is the header value (after the optional regex), or the OIDC `sub` claim. Values
  longer than 255 characters are stored as a SHA-256 hash.
- Comparisons are case-sensitive on every database. On MySQL and MariaDB the columns use the
  `utf8mb4_bin` collation, so two different subjects can't collide.

Renaming a user or changing their email doesn't break the mapping. Deleting a user removes
their mapping too.

## First login

When an identity has no mapping yet, the plugin creates a new account for it, if
`header_auto_create` or `oidc_auto_create` is on. Otherwise the login is refused.

- **Always a new account.** An identity is never attached to an existing account, even one
  with the same name or email, including the admin. Users can change their CTFd name and
  email, so a match doesn't prove it's the same person.
- **Name.** The account is named after the identity: the ID in header mode, or the
  `oidc_username_claim` in OIDC mode. If that name is taken, `-2`, `-3` and so on is added.
- **Email.** The account gets the email from `header_email_header` or the OIDC provider. If
  another account already uses that email, the new account is created without one.
- **Other details.** The account is verified and has no password. Creation respects CTFd's
  maximum number of users.

## Linked accounts and passwords

An account linked to an external identity, from either mode, is completely separate from
CTFd's password login. It signs in only through its identity, and it can't get a password:

- **Password login refused.** CTFd's login form rejects the account with "This account does
  not support password sign-on", even if it somehow has a password, for example from before
  it was linked.
- **No password from Settings.** Setting a password from the Settings page is refused.
  Without this rule, a user created by the proxy could set a password and then log in
  without going through the proxy.
- **No password resets.** "Forgot your password?" doesn't send a reset email to a linked
  account. The reply is the same as for an unknown address, so it doesn't reveal which emails
  belong to linked accounts. A reset link that was already sent is refused.
- **No password from admins.** In the admin panel's Edit User form for a linked account, the
  Password field and the "Require password change on next login" checkbox are hidden, and
  the server refuses both. Forcing a password change would otherwise lock the user out: CTFd
  would send them to a password reset they aren't allowed to complete. If a linked account
  already has that flag, for example from before the plugin was installed, it's cleared the
  next time CTFd tries to redirect them.
- **Email locked for users, not admins.** The email comes from the proxy or the identity
  provider, so users can't change it from Settings. The server refuses a changed
  email with "Your email is externally managed and cannot be changed". Admins can still
  correct it in the Edit User form. The plugin never uses the email to find an account, so
  changing it doesn't affect how the user signs in.

### The Settings page

For a linked account, the user's **Settings → Profile** page only shows what they can
actually change:

- **Password and Current Password** are hidden. They're also disabled, so they're never
  submitted.
- **Email** is shown read-only, with a grey background and the note above. If the account
  has no email, the field is empty with a "No email" placeholder.
- **Everything else** (name, affiliation, website, country, language) works as normal.

Accounts created through CTFd itself see the normal page. Like the login page, this works with
any theme: tested with `core` and Challenge Express, including saving the form.

One related CTFd quirk is handled: for an account without an email, CTFd's core theme renders
the email as the text `None` and submits it on save, which CTFd then rejects. For linked
accounts the plugin treats that as unchanged, so these users can save their profile.
- **Other accounts unchanged.** Accounts created through CTFd itself keep password login.
  That includes the admin from the setup wizard and users an admin creates.

## Seeing how each user signs in

In the admin panel, users who sign in through the reverse proxy or OpenID Connect get
an **External** badge next to their name. It appears both in the user list (**Admin →
Users**) and on the user's own admin page. Normal password accounts have no badge.

Hover over the badge to see which method the user signs in with and their external ID, plus
the issuer for OpenID Connect.

To get the same information from a script, use the [admin API](api.md), or query the table
directly:

```sql
SELECT u.id, u.name, u.email,
       CASE WHEN i.provider = 'header' THEN 'reverse proxy' ELSE 'openid' END AS via,
       i.subject, u.created
FROM auth_tools_identities i
JOIN users u ON u.id = i.user_id
ORDER BY u.id;
```
