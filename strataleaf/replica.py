from .codec import digest, dumps, field, loads, scalar_token
from .errors import Conflict, ReplicationError
from .indexes import refresh_document
from .mvcc import checked_revision, latest_row, visible_rows


def _definitions(rows):
    """Canonical mapping of (collection, index) -> (field, unique flag)."""
    return {(row["collection"], row["name"]): (row["field"], int(row["unique_flag"])) for row in rows}


def _build_index(connection, collection, index_name, path, unique, revision):
    """Materialise one index from every document visible at ``revision``.

    Used only when an index first arrives (or its definition changes): the
    packet names just the changed keys, so completeness has to come from the
    replica's own document set rather than from the packet.
    """
    seen = set()
    for row in visible_rows(connection, collection, revision):
        token = scalar_token(field(loads(row["body"]), path))
        if token is None:
            continue
        if unique:
            if token in seen:
                raise Conflict("unique index conflict: " + index_name)
            seen.add(token)
        connection.execute("INSERT OR IGNORE INTO index_values VALUES (?,?,?,?)",
                           (collection, index_name, token, row["key"]))


def _reconcile_projection(connection, desired, revision):
    """Install new or changed index definitions, leaving unchanged ones alone.

    Unchanged definitions keep their rows: those rows were already complete and
    still describe the same documents.  Only a missing or redefined index is
    rebuilt, so a catalog-only packet does not wipe the projection of an index
    that the replica had been serving all along.
    """
    stored = _definitions(connection.execute("SELECT * FROM index_defs").fetchall())
    for collection, index_name in sorted(set(stored) - set(desired)):
        connection.execute("DELETE FROM index_values WHERE collection=? AND name=?", (collection, index_name))
        connection.execute("DELETE FROM index_defs WHERE collection=? AND name=?", (collection, index_name))
    for (collection, index_name), (path, unique) in sorted(desired.items()):
        previous = stored.get((collection, index_name))
        if previous == (path, unique):
            continue
        if previous is None:
            connection.execute("INSERT INTO index_defs VALUES (?,?,?,?)", (collection, index_name, path, unique))
        else:
            connection.execute("DELETE FROM index_values WHERE collection=? AND name=?", (collection, index_name))
            connection.execute("UPDATE index_defs SET field=?,unique_flag=? WHERE collection=? AND name=?",
                               (path, unique, collection, index_name))
        _build_index(connection, collection, index_name, path, unique, revision)


def _refresh_touched(connection, touched, revision):
    """Rewrite index rows for exactly the keys carried by the applied packet.

    All touched keys are cleared before any is re-added, so a value moved
    between keys across the applied commits cannot trip the unique check on an
    intermediate ordering.  Untouched keys are deliberately left alone: they
    keep the projection they already had, which is what preserves coverage for
    the large bulk of documents a small packet never mentions.
    """
    connection.executemany("DELETE FROM index_values WHERE collection=? AND key=?", sorted(touched))
    for collection, key in sorted(touched):
        row = latest_row(connection, collection, key, revision)
        if row is not None and row["body"] is not None:
            refresh_document(connection, collection, key, loads(row["body"]))


class Replication:
    def __init__(self, store):
        self.store = store

    def export(self, since, limit=100):
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ReplicationError("replication limit must be between 1 and 1000 commits")
        with self.store.read() as connection:
            since = checked_revision(self.store, since)
            commits = [loads(row[0]) for row in connection.execute("SELECT payload FROM commits WHERE rev>? ORDER BY rev LIMIT ?", (since, limit))]
            body = {"format": 1, "source": self.store.get("database_id"), "since": since,
                "through": commits[-1]["revision"] if commits else since,
                "catalog_epoch": int(self.store.get("catalog_epoch")), "head": int(self.store.get("head")), "floor": int(self.store.get("floor")),
                "collections": [dict(row) for row in connection.execute("SELECT * FROM collections ORDER BY name")],
                "indexes": [dict(row) for row in connection.execute("SELECT * FROM index_defs ORDER BY collection,name")],
                "commits": commits}
            return {"body": body, "sha256": digest(body)}

    def apply(self, envelope):
        try:
            body = envelope["body"]
            if envelope["sha256"] != digest(body) or body["format"] != 1:
                raise ReplicationError("replication envelope checksum/format mismatch")
            commits = body["commits"]
            expected = list(range(body["since"] + 1, body["through"] + 1))
            if [item["revision"] for item in commits] != expected or body["through"] > body["head"]:
                raise ReplicationError("replication envelope has a revision gap")
            with self.store.atomic() as connection:
                if self.store.get("mode") != "replica" or self.store.get("upstream") != body["source"]:
                    raise ReplicationError("envelope does not match configured upstream")
                head = int(self.store.get("head"))
                if body["since"] > head:
                    raise ReplicationError("missing preceding replication range")
                epoch = int(self.store.get("catalog_epoch"))
                if body["through"] < head or (body["through"] == head and body["catalog_epoch"] <= epoch):
                    # Nothing newer than what the replica already holds: this is
                    # how a packet saved before a catalog advance is refused
                    # instead of rolling the catalog (and its indexes) back.
                    return {"revision": head, "applied": 0}
                if body["catalog_epoch"] < epoch:
                    # One upstream exports monotonically newer catalog epochs,
                    # so this only happens for a packet saved before a catalog
                    # advance the replica already applied.  Its commits (if any)
                    # are still applied, but the newer catalog and projection
                    # must be kept: rolling them back would drop recently
                    # installed indexes and schemas.
                    stale_catalog = True
                else:
                    stale_catalog = False
                catalog_changed = body["catalog_epoch"] != epoch
                if catalog_changed and not stale_catalog:
                    for definition in body["collections"]:
                        connection.execute("INSERT INTO collections VALUES (?,?,?) ON CONFLICT(name) DO UPDATE SET schema=excluded.schema,generation=excluded.generation",
                                           (definition["name"], definition["schema"], definition["generation"]))
                applied = 0
                touched = set()
                for commit in commits:
                    revision = commit["revision"]
                    if revision <= head:
                        continue
                    for operation in commit["operations"]:
                        document = operation["document"]
                        connection.execute("INSERT INTO versions VALUES (?,?,?,?,?)", (operation["collection"], operation["key"], revision,
                            dumps(document) if document is not None else None, operation["expires_at"]))
                        touched.add((operation["collection"], operation["key"]))
                    connection.execute("INSERT INTO commits(rev,payload) VALUES (?,?)", (revision, dumps(commit)))
                    applied += 1
                self.store.set("head", body["through"])
                if catalog_changed and not stale_catalog:
                    self.store.set("catalog_epoch", body["catalog_epoch"])
                if body["through"] < body["head"]:
                    # Mid catch-up: withhold current indexes entirely.  Today's
                    # unique constraints must not reject a legal intermediate
                    # view, and an empty catalog makes equality queries fall
                    # back to the version scan.  The packet that reaches the
                    # exported head installs the projection below.
                    connection.execute("DELETE FROM index_values")
                    connection.execute("DELETE FROM index_defs")
                elif stale_catalog:
                    # Keep the newer catalog and its projection; only the keys
                    # carried by this packet may move.
                    _refresh_touched(connection, touched, body["through"])
                else:
                    desired = _definitions(body["indexes"])
                    stored = _definitions(connection.execute("SELECT * FROM index_defs").fetchall())
                    if stored != desired:
                        # Reaching the exported head (or a catalog-only advance):
                        # add exactly the missing or redefined indexes, built
                        # from the documents visible here.  Missing indexes are
                        # populated from the whole current view, never from the
                        # packet's keys alone.
                        _reconcile_projection(connection, desired, body["through"])
                    _refresh_touched(connection, touched, body["through"])
                return {"revision": body["through"], "applied": applied}
        except (KeyError, TypeError, ValueError) as exc:
            raise ReplicationError("malformed replication envelope") from exc
