"""Re-runnable audit of replica catch-up and index projection.

Timeline is driven by a real primary database and real export envelopes:

  revision 1  a={"code":"X","region":"east"}, stable={"code":"Z","region":"west"}
  backup      two read-only followers restored from revision 1
  revision 2  b={"code":"X","region":"east"}
  revision 3  delete a, c={"code":"C","region":"east"}   then unique index by_code
  export      segmented packets: (1..2) and (2..3); one-shot packet (1..3)
  catalog     by_region on region, no document commit; empty packet at revision 3
  replay      the packet saved before by_region, then the new packet again
  revision 4  rewrite b, delete c, add d
  catalog     drop by_code, then bump the schema, both without document commits
  bulk        thousands of untouched documents with a tiny packet
  random      reproducible mixed segmentation compared with one-shot catch-up

Every stage asserts document reads, equality-index reads (including which
access path was chosen), raw version/commit/index content, and deep inspection.
Only the measured ``apply_elapsed_ms`` varies between runs.

Run from the repository root:

    python3 -m examples.replica_projection
"""
import copy
import json
import random
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

from strataleaf import Archives, Conflict, Database, ReadOnly, ReplicationError
from strataleaf.codec import digest


def read(db_path):
    connection = sqlite3.connect(Path(db_path).resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        return {
            "head": int(dict(connection.execute("SELECT key,value FROM meta"))["head"]),
            "versions": [tuple(row) for row in connection.execute(
                "SELECT collection,key,rev,body,expires FROM versions ORDER BY collection,key,rev")],
            "commits": [tuple(row) for row in connection.execute(
                "SELECT rev,payload FROM commits ORDER BY rev")],
            "index_defs": [tuple(row) for row in connection.execute(
                "SELECT collection,name,field,unique_flag FROM index_defs ORDER BY collection,name")],
            "index_values": [tuple(row) for row in connection.execute(
                "SELECT collection,name,token,key FROM index_values ORDER BY collection,name,token,key")],
        }
    finally:
        connection.close()


def keys(page):
    return [item.key for item in page.records]


def equal_index(page, index_name):
    return page.plan["access"] == "equality_index" and page.plan["index"] == index_name


def rejected(call, error):
    try:
        call()
    except error as exc:
        return type(exc).__name__
    raise AssertionError("operation unexpectedly succeeded")


class Audit:
    def __init__(self):
        self.stages = {}

    def record(self, name, **facts):
        self.stages[name] = facts
        return facts

    def require(self, condition, message):
        if not condition:
            raise AssertionError(message)


def timeline(folder, audit):
    primary_path = folder / "primary.db"
    base = folder / "base.db"
    r1_path = folder / "replica_one.db"
    r2_path = folder / "replica_bulk.db"
    atomic_path = folder / "replica_atomic.db"

    with Database(primary_path) as primary:
        primary.catalog.create("docs", {"fields": {"code": "string", "region": "string"}})
        first = primary.batch().put("docs", "a", {"code": "X", "region": "east"}).put(
            "docs", "stable", {"code": "Z", "region": "west"}).commit().revision
        primary.archives.backup(base)
        for target in (r1_path, r2_path, atomic_path):
            Archives.restore(base, target, follower=True)

        primary.batch().put("docs", "b", {"code": "X", "region": "east"}).commit()
        primary.batch().delete("docs", "a").put(
            "docs", "c", {"code": "C", "region": "east"}).commit()
        primary.indexes.create("docs", "by_code", "code", unique=True)

        segmented = [primary.replication.export(first, limit=1),
                     primary.replication.export(first + 1, limit=1)]
        one_shot = primary.replication.export(first, limit=3)
        audit.require(segmented[0]["body"]["through"] == 2, "first segmented packet boundary")
        audit.require(segmented[1]["body"]["through"] == 3, "second segmented packet boundary")
        audit.require(one_shot["body"]["through"] == 3, "one-shot packet boundary")
        saved_before_catalog = copy.deepcopy(segmented[1])

        # Stage 1: first segmented packet only.  by_code exists upstream but
        # must not be enforced against this legal historical intermediate view.
        with Database(r1_path) as replica:
            applied = replica.replication.apply(segmented[0])
            code_x = replica.query("docs", {"field": "code", "op": "eq", "value": "X"})
            audit.record("segmented_after_revision_2",
                         applied=applied,
                         a=replica.get("docs", "a").document,
                         b=replica.get("docs", "b").document,
                         stable=replica.get("docs", "stable").document,
                         code_x=keys(code_x), code_x_plan=code_x.plan)
            audit.require(applied == {"revision": 2, "applied": 1}, "first packet applied once")
            audit.require(keys(code_x) == ["a", "b"], "both historical X documents are readable")

            # Stage 2: reaching the export head installs and validates the index.
            applied = replica.replication.apply(segmented[1])
            audit.require(replica.get("docs", "a") is None, "a is deleted after revision 3")
            code_x = replica.query("docs", {"field": "code", "op": "eq", "value": "X"})
            code_z = replica.query("docs", {"field": "code", "op": "eq", "value": "Z"})
            history = replica.query("docs", {"field": "code", "op": "eq", "value": "X"}, revision=2)
            inspect = replica.diagnostics.inspect(deep=True)
            audit.record("segmented_after_revision_3",
                         applied=applied, code_x=keys(code_x), code_x_plan=code_x.plan,
                         code_z=keys(code_z), code_z_plan=code_z.plan,
                         historical_x=keys(history), historical_plan=history.plan,
                         inspect_ok=inspect["ok"], inspect_issues=inspect["issues"])
            audit.require(applied == {"revision": 3, "applied": 1}, "second packet applied once")
            audit.require(keys(code_x) == ["b"] and equal_index(code_x, "by_code"), "X resolves to b through by_code")
            audit.require(keys(code_z) == ["stable"] and equal_index(code_z, "by_code"), "Z resolves to stable through by_code")
            audit.require(keys(history) == ["a", "b"], "historical read keeps pre-index truth")
            audit.require(inspect["ok"], "segmented replica passes deep inspection")

        # Stage 2b: the same upstream range delivered in one packet.
        with Database(r2_path) as replica:
            applied = replica.replication.apply(one_shot)
            code_x = replica.query("docs", {"field": "code", "op": "eq", "value": "X"})
            audit.record("one_shot_after_revision_3", applied=applied, code_x=keys(code_x),
                         code_x_plan=code_x.plan, inspect_ok=replica.diagnostics.inspect(deep=True)["ok"])
            audit.require(applied == {"revision": 3, "applied": 2}, "one-shot packet applied both commits")
            audit.require(keys(code_x) == ["b"] and equal_index(code_x, "by_code"), "one-shot X resolves through by_code")

        # Diff raw facts, not just head or fingerprint.
        one, two = read(r1_path), read(r2_path)
        audit.require(one == two, "segmented and one-shot replicas hold identical raw facts")
        audit.record("segment_equals_one_shot", raw_facts_equal=True,
                     versions=len(one["versions"]), commits=len(one["commits"]),
                     index_values=len(one["index_values"]))

        # Stage 3: catalog-only advance, no document commit.
        primary.indexes.create("docs", "by_region", "region")
        catalog_packet = primary.replication.export(3)
        audit.require(catalog_packet["body"]["commits"] == [], "catalog packet has no commits")
        audit.require(catalog_packet["body"]["through"] == 3, "catalog packet sits at revision 3")
        for path, label in ((r1_path, "segmented"), (r2_path, "one_shot")):
            with Database(path) as replica:
                applied = replica.replication.apply(catalog_packet)
                west = replica.query("docs", {"field": "region", "op": "eq", "value": "west"})
                code_x = replica.query("docs", {"field": "code", "op": "eq", "value": "X"})
                audit.record("catalog_only_" + label, applied=applied,
                             west=keys(west), west_plan=west.plan,
                             code_x=keys(code_x), code_x_plan=code_x.plan,
                             indexes=[item["name"] for item in replica.indexes.list("docs")],
                             inspect_ok=replica.diagnostics.inspect(deep=True)["ok"])
                audit.require(applied == {"revision": 3, "applied": 0}, "catalog packet adds no document commit")
                audit.require(keys(west) == ["stable"] and equal_index(west, "by_region"),
                              "unchanged stable is found through the new by_region index")
                audit.require(keys(code_x) == ["b"] and equal_index(code_x, "by_code"),
                              "existing by_code survives the catalog advance")

                # Replaying the packet saved before by_region existed must not
                # roll the catalog back or drop the new index.
                stale = replica.replication.apply(saved_before_catalog)
                west = replica.query("docs", {"field": "region", "op": "eq", "value": "west"})
                audit.record("stale_packet_replay_" + label, applied=stale,
                             indexes=[item["name"] for item in replica.indexes.list("docs")],
                             west=keys(west), west_plan=west.plan)
                audit.require(stale == {"revision": 3, "applied": 0}, "older same-revision packet is a no-op")
                audit.require(keys(west) == ["stable"] and equal_index(west, "by_region"),
                              "stale replay keeps by_region")

                repeated = replica.replication.apply(catalog_packet)
                audit.require(repeated == {"revision": 3, "applied": 0}, "catalog packet replay is a no-op")
                audit.require(len(replica.feed.read(0)) == 3, "replays create no extra commits")

        # Stage 4: a small packet after the catalog advance must leave untouched
        # keys in place and remove only the keys that moved.
        primary.batch().put("docs", "b", {"code": "X2", "region": "north"}).delete(
            "docs", "c").put("docs", "d", {"code": "D", "region": "east"}).commit()
        doc_packet = primary.replication.export(3)
        for path, label in ((r1_path, "segmented"), (r2_path, "one_shot")):
            with Database(path) as replica:
                applied = replica.replication.apply(doc_packet)
                checks = {value: replica.query("docs", {"field": "code", "op": "eq", "value": value})
                          for value in ("X", "X2", "Z", "D")}
                regions = {value: replica.query("docs", {"field": "region", "op": "eq", "value": value})
                           for value in ("west", "north", "east")}
                audit.record("incremental_" + label,
                             applied=applied,
                             code={value: keys(page) for value, page in checks.items()},
                             code_plans={value: page.plan for value, page in checks.items()},
                             regions={value: keys(page) for value, page in regions.items()},
                             region_plans={value: page.plan for value, page in regions.items()},
                             deleted_c=replica.get("docs", "c"),
                             historical_a=replica.get("docs", "a", 1).document,
                             inspect_ok=replica.diagnostics.inspect(deep=True)["ok"])
                audit.require(applied == {"revision": 4, "applied": 1}, "document packet applied once")
                audit.require(keys(checks["X"]) == [] and equal_index(checks["X"], "by_code"),
                              "moved-away X token leaves no stale index row")
                audit.require(keys(checks["X2"]) == ["b"] and equal_index(checks["X2"], "by_code"),
                              "rewritten b is projected under its new token")
                audit.require(keys(checks["Z"]) == ["stable"] and equal_index(checks["Z"], "by_code"),
                              "untouched stable keeps an index row")
                audit.require(keys(regions["west"]) == ["stable"] and equal_index(regions["west"], "by_region"),
                              "untouched stable is still found through by_region")
                audit.require(keys(regions["north"]) == ["b"] and equal_index(regions["north"], "by_region"),
                              "rewritten b moved to region north in the projection")
                audit.require(keys(regions["east"]) == ["d"], "new d is projected")
                audit.require(replica.get("docs", "c") is None, "deleted c is hidden")
                audit.require(replica.get("docs", "a", 1).document["code"] == "X",
                              "historical read of a survives catch-up")

        one, two = read(r1_path), read(r2_path)
        audit.require(one == two, "replicas remain identical after incremental packets")
        audit.require(one["index_defs"] == [("docs", "by_code", "code", 1), ("docs", "by_region", "region", 0)],
                      "catalog and epoch advanced exactly once")

        # Stage 4b: catalog-only drop of one index, then a schema-generation
        # bump with no document change, both delivered as empty packets.
        primary.indexes.drop("docs", "by_code")
        drop_packet = primary.replication.export(4)
        audit.require(drop_packet["body"]["commits"] == [], "index drop needs no document commit")
        with Database(r1_path) as replica:
            applied = replica.replication.apply(drop_packet)
            region = replica.query("docs", {"field": "region", "op": "eq", "value": "west"})
            audit.record("catalog_drop_index", applied=applied,
                         indexes=[item["name"] for item in replica.indexes.list("docs")],
                         region=keys(region), region_plan=region.plan,
                         inspect_ok=replica.diagnostics.inspect(deep=True)["ok"])
            audit.require(applied == {"revision": 4, "applied": 0}, "drop packet applies no commit")
            audit.require([item["name"] for item in replica.indexes.list("docs")] == ["by_region"],
                          "dropped index disappears, surviving index stays")
            audit.require(keys(region) == ["stable"] and equal_index(region, "by_region"),
                          "surviving index still answers after a drop")
            audit.require(replica.diagnostics.inspect(deep=True)["ok"], "drop keeps the projection consistent")

        generation = primary.catalog.describe("docs")["generation"]
        primary.catalog.evolve("docs", {"fields": {"code": "string", "region": "string", "note": "string"}},
                               generation)
        schema_packet = primary.replication.export(4)
        with Database(r2_path) as replica:
            applied = replica.replication.apply(schema_packet)
            audit.record("catalog_schema_only", applied=applied,
                         schema=replica.catalog.describe("docs")["schema"],
                         indexes=[item["name"] for item in replica.indexes.list("docs")],
                         region=keys(replica.query("docs", {"field": "region", "op": "eq", "value": "west"})),
                         inspect_ok=replica.diagnostics.inspect(deep=True)["ok"])
            audit.require(applied == {"revision": 4, "applied": 0}, "schema packet applies no commit")
            audit.require("note" in replica.catalog.describe("docs")["schema"]["fields"],
                          "schema-only packet advances the catalog")
            audit.require(len(replica.feed.read(0)) == 4, "catalog packets create no document commits")

    # Stage 5: gap rejection, failed-packet atomicity and read-only enforcement
    # on a follower that is still at the backup revision.
    with Database(atomic_path) as replica:
        with Database(primary_path) as primary:
            before = read(atomic_path)
            gap = rejected(lambda: replica.replication.apply(primary.replication.export(2)), ReplicationError)
            readonly = rejected(lambda: replica.batch().delete("docs", "a").commit(), ReadOnly)

        forged = copy.deepcopy(segmented[0])
        forged["body"]["head"] = 2
        forged["body"]["commits"] = [{"revision": 2, "operations": [
            {"collection": "docs", "key": "q1", "document": {"code": "X", "region": "east"},
             "expected": None, "expires_at": None},
            {"collection": "docs", "key": "q2", "document": {"code": "X", "region": "east"},
             "expected": None, "expires_at": None}]}]
        forged["sha256"] = digest(forged["body"])
        conflict = rejected(lambda: replica.replication.apply(forged), Conflict)
        after = read(atomic_path)
        audit.require(before == after, "failed packet leaves no partial state")
        audit.require(before["head"] == 1, "failed packet does not move the replica head")
        audit.record("safety", gap=gap, readonly=readonly, unique_conflict=conflict,
                     head_after_failures=after["head"], unchanged=before == after)


def projection_rowids(db_path):
    """Row identity of every current index entry, as an external observer sees it."""
    connection = sqlite3.connect(Path(db_path).resolve().as_uri() + "?mode=ro", uri=True)
    try:
        return {(row[0], row[1], row[2]): row[3] for row in connection.execute(
            "SELECT collection,token,key,rowid FROM index_values")}
    finally:
        connection.close()


def bulk(folder, audit):
    primary_path = folder / "bulk_primary.db"
    base = folder / "bulk_base.db"
    replica_path = folder / "bulk_replica.db"
    documents = 3000
    untouched_name, moved_name, deleted_name = "doc_00001", "doc_00007", "doc_02000"
    with Database(primary_path) as primary:
        primary.catalog.create("docs", {"fields": {"code": "string", "region": "string"}})
        for start in range(0, documents, 1000):
            batch = primary.batch()
            for number in range(start, min(start + 1000, documents)):
                batch.put("docs", f"doc_{number:05}", {"code": f"C{number:05}", "region": "east"})
            batch.commit()
        primary.indexes.create("docs", "by_code", "code", unique=True)
        boundary = primary.revision
        primary.archives.backup(base)
        Archives.restore(base, replica_path, follower=True)

        primary.batch().put("docs", moved_name, {"code": "C00007b", "region": "west"}).put(
            "docs", "doc_01234", {"code": "C01234", "region": "west"}).delete("docs", deleted_name).commit()
        packet = primary.replication.export(boundary)
        audit.require(len(packet["body"]["commits"]) == 1, "bulk packet carries one commit")

        with Database(replica_path) as replica:
            before = projection_rowids(replica_path)
            started = time.perf_counter()
            applied = replica.replication.apply(packet)
            elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
            after = projection_rowids(replica_path)
            untouched = replica.query("docs", {"field": "code", "op": "eq", "value": "C00001"})
            moved = replica.query("docs", {"field": "code", "op": "eq", "value": "C00007"})
            rewritten = replica.query("docs", {"field": "code", "op": "eq", "value": "C00007b"})
            removed = replica.query("docs", {"field": "code", "op": "eq", "value": "C02000"})
            inspect = replica.diagnostics.inspect(deep=True)
            # An untouched document's index row must keep its physical identity:
            # it was not deleted and reinserted by this packet.
            kept_rows = [(identity, before[identity]) for identity in before if identity[2] == untouched_name]
            untouched_rows_kept = bool(kept_rows) and all(
                after.get(identity) == rowid for identity, rowid in kept_rows)
            audit.record("bulk_unchanged",
                         applied=applied,
                         packet_operations=len(packet["body"]["commits"][0]["operations"]),
                         apply_elapsed_ms=elapsed_ms,
                         untouched=keys(untouched), untouched_plan=untouched.plan,
                         untouched_rows_kept=untouched_rows_kept,
                         moved_away=keys(moved), rewritten=keys(rewritten),
                         deleted=keys(removed), index_rows=len(after),
                         inspect_ok=inspect["ok"], inspect_issues=inspect["issues"])
            audit.require(applied == {"revision": boundary + 1, "applied": 1}, "bulk packet applied")
            audit.require(untouched_rows_kept,
                          "index rows for keys outside the packet are never rewritten")
            audit.require(len(after) == documents - 1, "projection covers every live document")
            audit.require(keys(untouched) == [untouched_name] and equal_index(untouched, "by_code"),
                          "untouched key remains reachable through the index")
            audit.require(keys(moved) == [] and keys(rewritten) == [moved_name],
                          "moved key leaves no stale token")
            audit.require(keys(removed) == [], "deleted key leaves no stale token")
            audit.require(inspect["ok"], "bulk replica passes deep inspection")


def segmented_equivalence(folder, audit):
    """Random but reproducible segmentation must match one-shot catch-up.

    Packet boundaries vary, commits interleave deletes and value moves between
    unique index tokens, and catalog changes (index create/drop) land between
    them.  Equality of head/epoch alone is not used: raw versions, commits,
    index definitions/rows and each query's access path are compared.
    """
    rng = random.Random(20261120)
    primary_path = folder / "fuzz_primary.db"
    base = folder / "fuzz_base.db"
    segmented_path = folder / "fuzz_segmented.db"
    one_shot_path = folder / "fuzz_one_shot.db"
    document_keys = [f"k{number}" for number in range(12)]
    with Database(primary_path) as primary:
        primary.catalog.create("docs", {"fields": {"code": "string", "region": "string"}})
        primary.batch().put("docs", "seed", {"code": "S", "region": "east"}).commit()
        start = primary.revision
        primary.archives.backup(base)
        Archives.restore(base, segmented_path, follower=True)
        Archives.restore(base, one_shot_path, follower=True)

        rounds = 40
        for round_number in range(rounds):
            batch, chosen = primary.batch(), set()
            for _ in range(rng.randint(1, 3)):
                key = rng.choice(document_keys)
                if key in chosen:
                    continue
                chosen.add(key)
                if rng.random() < 0.25:
                    batch.delete("docs", key)
                else:
                    batch.put("docs", key, {"code": f"c{rng.randint(0, 5)}",
                                            "region": rng.choice(["east", "west", "north"])})
            try:
                if batch.operations:
                    batch.commit()
            except Conflict:
                pass
            if rng.random() < 0.2:
                try:
                    primary.indexes.create("docs", f"i{round_number}", rng.choice(["code", "region"]),
                                           unique=rng.random() < 0.3)
                except Conflict:
                    pass
            elif rng.random() < 0.1:
                existing = [item["name"] for item in primary.indexes.list("docs")]
                if existing:
                    primary.indexes.drop("docs", rng.choice(existing))

        with Database(segmented_path) as segmented, Database(one_shot_path) as one_shot:
            sizes = []
            while segmented.revision < primary.revision:
                limit = rng.choice([1, 1, 2, 5, 17])
                sizes.append(limit)
                segmented.replication.apply(primary.replication.export(segmented.revision, limit=limit))
            one_shot.replication.apply(primary.replication.export(start, limit=1000))
            segmented_facts, one_shot_facts = read(segmented_path), read(one_shot_path)
            audit.require(segmented_facts == one_shot_facts,
                          "random segmentation matches one-shot catch-up")
            audit.require(segmented.diagnostics.inspect(deep=True)["ok"], "segmented fuzz replica is consistent")
            audit.require(one_shot.diagnostics.inspect(deep=True)["ok"], "one-shot fuzz replica is consistent")
            audit.require(segmented.diagnostics.fingerprint() == primary.diagnostics.fingerprint(),
                          "segmented replica matches the primary read view")
            matched = {}
            for predicate in ({"field": "code", "op": "eq", "value": "c3"},
                              {"field": "region", "op": "eq", "value": "west"}):
                indexed = keys(segmented.query("docs", predicate, limit=100))
                scanned = keys(segmented.query("docs", predicate, limit=100, force_scan=True))
                other = keys(one_shot.query("docs", predicate, limit=100))
                audit.require(indexed == scanned == other,
                              "index and scan agree on every replica")
                matched[str(predicate)] = indexed
            audit.record("segmented_equivalence",
                         discovery=start, commits=rounds, packet_sizes=sizes,
                         versions=len(segmented_facts["versions"]),
                         commit_payloads=len(segmented_facts["commits"]),
                         index_defs=len(segmented_facts["index_defs"]),
                         index_values=len(segmented_facts["index_values"]),
                         raw_facts_equal=True, queries=matched)


def main():
    audit = Audit()
    with tempfile.TemporaryDirectory(prefix="strataleaf-replica-audit-") as directory:
        folder = Path(directory)
        timeline(folder, audit)
        bulk(folder, audit)
        segmented_equivalence(folder, audit)
    print(json.dumps({"stages": audit.stages}, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    sys.exit(main())
