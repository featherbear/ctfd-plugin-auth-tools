# Installation

## Requirements

- CTFd 3.8. Built and tested against 3.8.9.
- SQLite, MySQL or MariaDB, the same databases CTFd supports.
- No extra Python packages. The plugin only uses what CTFd already ships.

## Install the plugin

CTFd loads plugins from its `CTFd/plugins/` directory. The plugin's directory must be named
`auth_tools`.

### Plain install

```sh
cp -r auth_tools /path/to/CTFd/CTFd/plugins/auth_tools
```

Then restart CTFd.

### Docker

Mount the directory into the official image:

```yaml
services:
  ctfd:
    image: ctfd/ctfd:3.8.9
    volumes:
      - ./auth_tools:/opt/CTFd/CTFd/plugins/auth_tools:ro
```

Or build it into your own image:

```dockerfile
FROM ctfd/ctfd:3.8.9
COPY auth_tools /opt/CTFd/CTFd/plugins/auth_tools
```

## What happens on startup

The plugin creates one table, `auth_tools_identities`, which maps external identities to CTFd
users. See [How accounts are matched](accounts.md).

- **SQLite:** the table is created directly.
- **MySQL/MariaDB:** the plugin runs its own Alembic migration and records the version in
  CTFd's config table as `auth_tools_alembic_version`.

Startup is safe to repeat. Restarting CTFd doesn't recreate or change the table.

## Check that it loaded

Log in as an admin. **Auth Tools** should appear in the admin navigation bar, linking to
`/admin/auth_tools`.

The plugin starts in `off` mode, so it changes nothing until you choose a login method. Next,
see [Configuration](configuration.md).

## Upgrading

Replace the `auth_tools` directory and restart CTFd. Any new migrations run automatically.

## Uninstalling

Set the mode to `off`, then remove the `auth_tools` directory and restart CTFd. The accounts
the plugin created stay in CTFd, but they have no password. To let those users log in with a
password, an admin has to set one for each account in the admin panel.

The `auth_tools_identities` table and the `auth_tools_*` config rows are left in the database.
Drop or delete them by hand if you want them gone.
