import contextlib
import datetime
import io
import json
import pathlib
import tempfile
import unittest
from unittest import mock

import research_wiki


class ResearchRefreshTests(unittest.TestCase):
    def test_identical_refresh_is_byte_for_byte_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            page = {"pageid": 1, "title": "UTM/Test", "revisions": [{
                "revid": 42, "timestamp": "2026-01-01T00:00:00Z",
                "slots": {"main": {"*": "Synthetic documentation [[UTM/Example]]"}},
            }]}
            with mock.patch.object(research_wiki, "ROOT", root), \
                 mock.patch.object(research_wiki, "CACHE", root / "cache"), \
                 mock.patch.object(research_wiki, "inventory", return_value=[page]), \
                 mock.patch.object(research_wiki, "fetch", return_value=[page]), \
                 mock.patch("sys.argv", ["research_wiki.py"]), \
                 mock.patch.object(research_wiki.datetime, "datetime") as clock, \
                 contextlib.redirect_stdout(io.StringIO()):
                clock.now.return_value = datetime.date(2026, 1, 1)
                research_wiki.main()
                output = root / "docs/securepoint/wiki-manifest.json"
                first = output.read_bytes()
                clock.now.return_value = datetime.date(2026, 1, 2)
                research_wiki.main()
                self.assertEqual(first, output.read_bytes(), "unchanged research would open a timestamp-only PR")
                # A genuine revision and retrieval failures must still be published.
                page["revisions"][0]["revid"] = 43
                research_wiki.main()
                updated = json.loads(output.read_text())
                self.assertEqual(updated["pages"][0]["revision"], 43)
                self.assertEqual(updated["retrieved_at"], "2026-01-02")
                page["retrieval_error"] = "documentation unavailable"
                research_wiki.main()
                self.assertEqual(json.loads(output.read_text())["pages"][0]["retrieval_error"],
                                 "documentation unavailable")


if __name__ == "__main__":
    unittest.main()
