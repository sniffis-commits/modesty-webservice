"""Tests for the IMDb Top 200 catalog and the open-API submission ledger."""

import importlib.util
import os
import sqlite3
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "packages", "nsfw-webservice", "src"))
import cache_db  # noqa: E402


def _load_seeder():
    path = os.path.join(ROOT, "seed_imdb_top200.py")
    spec = importlib.util.spec_from_file_location("seed_imdb_top200", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CacheDBCatalogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = cache_db.CacheDB(os.path.join(self.tmp.name, "test.sqlite"))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_catalog_seed_is_additive_and_idempotent(self):
        rows = [(1, "tt0111161", "The Shawshank Redemption"),
                (2, "tt0068646", "The Godfather")]
        self.assertEqual(self.db.seed_title_catalog(rows), 2)
        self.assertEqual(self.db.seed_title_catalog(rows), 0)
        self.assertEqual(len(self.db.get_title_catalog()), 2)
        entry = self.db.get_title_catalog("tt0111161")
        self.assertEqual(entry["title"], "The Shawshank Redemption")
        self.assertEqual(entry["rank"], 1)
        self.assertIsNone(self.db.get_title_catalog("tt9999999"))

    def test_get_community_ratings_uses_current_schema(self):
        # GET /v1/hash calls this for every lookup. The old query selected
        # `source`/`verdict` columns that media_hashes no longer has, which
        # crashed the handler and produced an empty HTTP response.
        self.assertEqual(self.db.get_community_ratings("a" * 64), [])
        self.db.put_hash("b" * 64, 6, None, None, 0,
                         source_id=self.db.source_id("community"))
        result = self.db.get_community_ratings("b" * 64)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["rating"], 6)
        self.assertEqual(result[0]["verdict"], "romance")
        self.assertEqual(result[0]["count"], 1)
        self.assertEqual(self.db.get_community_ratings("c" * 64), [])

    def test_submissions_recorded_by_imdb_id(self):
        self.db.seed_title_catalog([(1, "tt0111161", "The Shawshank Redemption")])
        self.db.record_v1_submission("tt0111161", "a" * 64, 10,
                                     "explicit", "video", "film.mp4")
        # Re-reporting the same bytes updates instead of duplicating.
        self.db.record_v1_submission("tt0111161", "a" * 64, 7,
                                     "revealing", "video", "film.mp4")
        subs = self.db.get_v1_submissions("tt0111161")
        self.assertEqual(len(subs), 1)
        self.assertEqual(subs[0]["rating"], 7)
        self.assertEqual(subs[0]["verdict"], "revealing")
        self.assertEqual(self.db.get_v1_submissions("tt0068646"), [])


class CanonicalCatalogTests(unittest.TestCase):
    def test_csv_has_two_hundred_unique_titles(self):
        seeder = _load_seeder()
        rows = seeder.load_catalog(seeder.DEFAULT_CSV)
        self.assertEqual(len(rows), 200)
        self.assertEqual(len({r[1] for r in rows}), 200)
        self.assertEqual(len({r[2] for r in rows}), 200)
        self.assertTrue(all(r[1].startswith("tt") for r in rows))


class ProductCatalogSeedTests(unittest.TestCase):
    """The parents guide reads nsfw.sqlite, not app.sqlite."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "nsfw.sqlite")
        conn = sqlite3.connect(self.path)
        # The old strict schema the product DB shipped with.
        conn.executescript("""
        CREATE TABLE community_hashes (
            hash TEXT PRIMARY KEY, rating INTEGER NOT NULL, verdict TEXT,
            reason TEXT, source TEXT DEFAULT 'community', imdb_id TEXT,
            title TEXT, filename_hint TEXT, created_utc INTEGER, updated_utc INTEGER);
        CREATE TABLE title_releases (
            id INTEGER PRIMARY KEY AUTOINCREMENT, imdb_id TEXT NOT NULL,
            hash TEXT NOT NULL REFERENCES community_hashes(hash),
            release_type TEXT, quality TEXT, alignment_offset_sec REAL,
            UNIQUE(imdb_id, hash));
        """)
        conn.execute(
            "INSERT INTO community_hashes (hash, rating, source, imdb_id, title) "
            "VALUES (?,?,?,?,?)",
            ("a" * 64, 10, "admin", "tt0111161", "Demo film"))
        conn.execute(
            "INSERT INTO title_releases (imdb_id, hash, release_type, quality) "
            "VALUES (?,?,?,?)",
            ("tt0111161", "a" * 64, "theatrical", "1080p"))
        conn.commit()
        conn.close()

    def tearDown(self):
        self.tmp.cleanup()

    def test_migrates_to_relational_model_and_is_idempotent(self):
        seeder = _load_seeder()
        rows = seeder.load_catalog(seeder.DEFAULT_CSV)
        seeder.seed_product_db(self.path, rows)
        seeder.seed_product_db(self.path, rows)  # must not duplicate

        conn = sqlite3.connect(self.path)
        try:
            # Titles are metadata; files and releases stay as real rows only.
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM title_catalog").fetchone()[0], 200)
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM community_hashes").fetchone()[0], 1)
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM title_releases").fetchone()[0], 1)
            # The existing demo file/release survives and stays linked.
            self.assertEqual(conn.execute(
                "SELECT rating FROM community_hashes WHERE hash=?",
                ("a" * 64,)).fetchone()[0], 10)
            # Real keys exist: a release points to both its title and its file.
            rel_fks = {r[2] for r in conn.execute(
                "PRAGMA foreign_key_list(title_releases)")}
            self.assertEqual(rel_fks, {"title_catalog", "community_hashes"})
            comm_fks = {r[2] for r in conn.execute(
                "PRAGMA foreign_key_list(community_hashes)")}
            self.assertEqual(comm_fks, {"title_catalog"})
            # The pages' relation works: file -> release -> title meta ID.
            joined = conn.execute(
                "SELECT t.title, tr.release_type, ch.rating "
                "FROM community_hashes ch "
                "JOIN title_releases tr ON tr.hash = ch.hash "
                "JOIN title_catalog t ON t.imdb_id = tr.imdb_id"
            ).fetchall()
            self.assertEqual(len(joined), 1)
            self.assertEqual(joined[0], ("The Shawshank Redemption",
                                         "theatrical", 10))
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
