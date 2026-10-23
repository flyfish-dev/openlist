# Flyfish OpenList Integration

This fork is based on **OpenList v4.2.7**. The server implementation is unchanged;
the Flyfish integration adds a reviewed migration helper, tests and a reproducible
custom-frontend deployment pattern. Backend AGPL-3.0 and upstream notices remain.
The matching frontend is [flyfish-dev/openlist-web](https://github.com/flyfish-dev/openlist-web/tree/flyfish).

## Safe Migration From Recent AList

Read the [official migration guide](https://doc.oplist.org/guide/migrate).
AList 3.46 and later must not be migrated by simply swapping binaries or copying
its SQLite database over OpenList's new schema.

1. Preserve a private application JSON export, consistent full `data` backup,
   service definition, external mount configuration and offline-download files.
2. Start a **fresh**, loopback-only OpenList data directory. Keep live AList and
   production ingress unchanged during the preflight. In an isolated bootstrap,
   `OPENLIST_ADMIN_PASSWORD` creates the initial admin before the guest account;
   use an ephemeral random value, never an actual user's password in a command.
3. Run `migrate_alist.py import` against that isolated API using the JSON export.
   It imports through the same administrative APIs as Backup & Restore, creates
   local storage skeletons, refreshes retired branding settings and fails closed on
   unsupported user/role mappings. No source data is modified.
4. Stop the isolated server, then run `seal`. This restores private password
   hashes/salts, password timestamps, 2FA and passkeys omitted by the JSON export,
   and copies compatible storage/search/task/SSH-key tables into the fresh schema.
   Real storage adapters stay disabled: `CreateStorage` initializes a provider
   even when its disabled bit is set, so provider secrets are restored offline.
5. Review the credential-free report and the original ACLs. Array-based AList
   roles only migrate automatically if a single, uniform path scope maps without
   broadening access. Multiple path-specific grants require a human ACL design.
   Historical login sessions are not portable and require a new login.
6. Review current OpenList defaults; preserve tokens, signing secrets, metadata
   passwords, provider credentials and needed native-preview preferences. Apply
   the brand and `proxy_types` delta from the frontend's generated catalog.
7. Verify storage driver availability, cloud mounts, writable local bind mounts,
   aria2 networking, hashes, directory ACLs, representative previews and an
   actual restore point on a second machine. Cut over ingress only after tests.
8. Retire the old binary and unit only after the production and backup checks.
   Retain the private rollback backup; never publish it with this source.

Example commands (target stopped for the final command):

```sh
python3 tools/flyfish/migrate_alist.py import \
  --source /private/backup/source.db \
  --export /private/backup/application.json \
  --target /srv/openlist/data/data.db --url http://127.0.0.1:15244
python3 tools/flyfish/migrate_alist.py seal \
  --source /private/backup/source.db --target /srv/openlist/data/data.db
python3 -m unittest discover -s tools/flyfish -p 'test_*.py'
```

The helper intentionally refuses additional-account ID ambiguity and lossy role
conversions. It is not an unattended universal converter for arbitrary future
AList schemas. Unrepresented source tables are reported and retained in the
private original database, never silently discarded.

## Container Layout

See `compose.example.yaml` and replace the host paths. Include
`nginx-assets.example.conf` inside your HTTPS server block and install
`nginx-preview-mime.types` as `/etc/nginx/snippets/flyfish-preview-mime.types`: the upstream backend
only exposes its standard static prefixes, so custom public Worker/logo paths
must not fall through to its HTML SPA page. Label this public web directory with
the supplied shared-web SELinux type when serving it through Nginx and a container.
Download current images
on the destination and pin their verified multiarch manifest digest. Do not
copy raw Postgres directories or architecture-specific binaries between ARM64
and AMD64. Do not bind OpenList's temporary directory to a general download
folder: startup may clean it. Share a dedicated temporary subdirectory with
aria2 only when required, and preserve pending jobs before moving it.

OneDrive FUSE needs a propagated mount and an explicit SELinux policy for the
application container. Do not disable host SELinux or mount the entire host.
Keep 5244 and aria2 RPC private; publish HTTPS through Nginx. Azure-style cold
standbys must retain consistent data/configuration and **not run writable copies**
or cloud mounts until the primary has been fenced.

## Security And Source

Use signed same-origin OpenList file endpoints for the enhanced preview formats.
Provider secrets, exports, `config.json`, vault files, `.env` files and real share
tokens do not belong in Git. Keep upstream credits and expose both source links
in the deployed UI. This repository contains no production access credentials.
