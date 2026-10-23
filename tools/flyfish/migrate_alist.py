#!/usr/bin/env python3
"""Application-level migration, with an offline preservation pass for private fields.

The source is never modified. Bootstrap a fresh OpenList data directory first;
run `import` against an isolated loopback instance, stop it, then run `seal`.
Keep the original export and data backup: sessions and path-dependent roles
that have no lossless OpenList representation are not silently downgraded.
"""

import argparse
import contextlib
import hashlib
import json
import os
import pathlib
import posixpath
import sqlite3
import urllib.error
import urllib.parse
import urllib.request

AUTH_FIELDS = ("pwd_hash", "pwd_ts", "salt", "otp_secret", "authn")
COPY_TABLES = ("x_search_nodes", "x_task_items", "x_ssh_public_keys", "x_storages", "x_meta")
REFRESH = {"version", "index_progress", "logo", "favicon", "main_color", "audio_cover",
           "site_title", "announcement", "customize_head", "customize_body"}


@contextlib.contextmanager
def database(path, readonly=False):
    value = pathlib.Path(path).resolve()
    connection = sqlite3.connect(value.as_uri() + ("?mode=ro" if readonly else "?mode=rw"), uri=True)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
    finally:
        connection.close()


def text(value):
    return value.decode() if isinstance(value, bytes) else value


def convert_user(user, roles):
    result = {key: text(value) for key, value in dict(user).items()}
    if 'disabled' in result:
        result['disabled'] = bool(result['disabled'])
    original_role = result["role"]
    if isinstance(original_role, int) or str(original_role) in ("0", "1", "2"):
        result["role"] = int(original_role)
        return result
    ids = json.loads(original_role)
    selected = [roles[identifier] for identifier in ids]
    names = {row["name"] for row in selected}
    if "admin" in names:
        result.update(role=2, base_path="/", permission=65535)
        return result
    scopes = [scope for row in selected for scope in json.loads(text(row["raw_permission"]) or "[]")]
    paths = {posixpath.normpath(scope["path"]) for scope in scopes}
    permissions = {int(scope["permission"]) for scope in scopes}
    if len(paths) != 1 or len(permissions) != 1:
        raise ValueError("Path-dependent or empty roles require an explicit ACL design; migration refused")
    base = posixpath.normpath(result.get("base_path") or "/")
    scope = paths.pop()
    if base == "/" or scope == base or scope.startswith(base.rstrip("/") + "/"):
        base = scope
    elif not base.startswith(scope.rstrip("/") + "/"):
        raise ValueError("User base path and role scope are disjoint")
    result.update(role=1 if "guest" in names else 0, base_path=base, permission=permissions.pop())
    return result


def source_users(source):
    names = {row[0] for row in source.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    roles = {row["id"]: dict(row) for row in source.execute("SELECT * FROM x_roles")} if "x_roles" in names else {}
    return [convert_user(row, roles) for row in source.execute("SELECT * FROM x_users ORDER BY id")]


class Application:
    def __init__(self, url, target):
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("Migration API must be an isolated loopback HTTP endpoint")
        self.url = url.rstrip("/") + "/api"
        self.client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with database(target, True) as connection:
            self.token = text(connection.execute("SELECT value FROM x_setting_items WHERE key='token'").fetchone()[0])

    def request(self, path, data=None):
        request = urllib.request.Request(self.url + path, headers={"Authorization": self.token, "Content-Type": "application/json"},
                                         data=json.dumps(data).encode() if data is not None else None)
        try:
            with self.client.open(request, timeout=45) as response:
                value = json.load(response)
        except urllib.error.HTTPError as error:
            raise RuntimeError("Migration API HTTP failure at " + path) from error
        if value.get("code") != 200:
            # Error bodies can echo a provider's secrets: never print them.
            raise RuntimeError("Migration API rejected " + path + " (code " + str(value.get("code")) + ")")
        return value.get("data")


def import_application(args):
    exported = json.loads(pathlib.Path(args.export).read_text())
    if exported.get("encrypted"):
        raise ValueError("Decrypt the application export in a private offline environment first")
    api = Application(args.url, args.target)
    defaults = {row["key"]: row for row in api.request("/admin/setting/list")}
    with database(args.source, True) as source:
        users = source_users(source)
    existing = {row["username"]: row for row in api.request("/admin/user/list?per_page=10000&page=1")["content"]}
    for user in users:
        item = {key: value for key, value in user.items() if key not in AUTH_FIELDS}
        item["password"] = ""
        if user["username"] in existing:
            assert existing[user["username"]]["id"] == user["id"], "Default account IDs differ"
            api.request("/admin/user/update", item)
        else:
            raise ValueError("Additional users need an explicit create-and-ID preservation plan")
    for kind, singular in (("storages", "storage"), ("metas", "meta")):
        for original in exported[kind]:
            item = dict(original)
            if kind == "storages":
                item["disabled"] = True
                # CreateStorage initializes providers even when disabled. Import
                # local skeletons; restore real providers offline in `seal`.
                item['driver'] = 'Local'
                item['addition'] = json.dumps({'root_folder_path': '/opt/openlist/data/import-sandbox'})
            api.request("/admin/" + singular + "/create", item)
    settings = []
    skipped = []
    for item in exported["settings"]:
        key = item["key"]
        if key not in defaults or key in REFRESH:
            skipped.append(key)
            continue
        settings.append(dict(defaults[key], value=item["value"]))
    api.request("/admin/setting/save", settings)
    print(json.dumps({"application_import": True, "users": len(users), "storages_disabled": len(exported["storages"]),
                      "metas": len(exported["metas"]), "settings": len(settings), "refreshed_or_retired_keys": skipped}))


def quoted(name):
    return '"' + name.replace('"', '""') + '"'


def seal(args):
    report = {"private_auth_preserved": True, "copied_tables": {}, "unrepresented_tables": {}, "users": []}
    with database(args.source, True) as source, database(args.target) as target, target:
        assert source.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        source_names = {row[0] for row in source.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
        target_names = {row[0] for row in target.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for user in source_users(source):
            columns = AUTH_FIELDS + ("base_path", "role", "permission")
            target.execute("UPDATE x_users SET " + ",".join(quoted(key) + "=?" for key in columns) + " WHERE id=?",
                           [user.get(key) for key in columns] + [user["id"]])
            actual = target.execute("SELECT * FROM x_users WHERE id=?", (user["id"],)).fetchone()
            assert actual and all(text(actual[key]) == text(user.get(key)) for key in columns)
            report["users"].append({key: user[key] for key in ("id", "username", "base_path", "role", "permission")})
        for table in COPY_TABLES:
            if table not in source_names:
                continue
            assert table in target_names, "A source data table has no target representation"
            columns = [row["name"] for row in source.execute("PRAGMA table_info(" + quoted(table) + ")")]
            available = {row["name"] for row in target.execute("PRAGMA table_info(" + quoted(table) + ")")}
            inverted = {'down_proxy_sign': 'disable_proxy_sign'} if table == 'x_storages' else {}
            retired = set(columns) - available - inverted.keys()
            assert not retired or all(source.execute('SELECT count(*) FROM ' + quoted(table) + ' WHERE '
                + quoted(column) + " IS NOT NULL AND " + quoted(column) + " NOT IN ('',0)").fetchone()[0] == 0
                for column in retired), "A non-empty source data column has no target representation"
            source_columns = [column for column in columns if column in available or column in inverted]
            columns = [inverted.get(column, column) for column in source_columns]
            expressions = [('NOT ' + quoted(column)) if column in inverted else quoted(column) for column in source_columns]
            rows = source.execute("SELECT " + ",".join(expressions) + " FROM " + quoted(table)).fetchall()
            target.execute("DELETE FROM " + quoted(table))
            target.executemany("INSERT INTO " + quoted(table) + " (" + ",".join(map(quoted, columns)) + ") VALUES (" + ",".join("?" for _ in columns) + ")", rows)
            assert target.execute("SELECT count(*) FROM " + quoted(table)).fetchone()[0] == len(rows)
            report["copied_tables"][table] = len(rows)
            if table == 'x_storages':
                target.execute('UPDATE x_storages SET disabled=1')
        for table in source_names - target_names:
            report["unrepresented_tables"][table] = source.execute("SELECT count(*) FROM " + quoted(table)).fetchone()[0]
        assert target.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    report["source_sha256"] = hashlib.sha256(pathlib.Path(args.source).read_bytes()).hexdigest()
    print(json.dumps(report, indent=2))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("import", "seal"))
    parser.add_argument("--source", required=True, help="Consistent, private AList SQLite backup")
    parser.add_argument("--target", required=True, help="Fresh OpenList SQLite database")
    parser.add_argument("--export", help="Unencrypted application JSON export (keep private)")
    parser.add_argument("--url", default="http://127.0.0.1:15244")
    args = parser.parse_args()
    if args.command == "import":
        assert args.export
        import_application(args)
    else:
        seal(args)


if __name__ == "__main__":
    main()
