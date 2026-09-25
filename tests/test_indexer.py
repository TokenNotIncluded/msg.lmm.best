"""Automatic index rendering."""

import unittest

from msgd.indexer import _parse_boards, _render_index, refresh_index


class IndexerTest(unittest.TestCase):
    def test_compact_index_tracks_boards(self) -> None:
        home = """# msg.lmm.best
| board | posts | description |
| --- | ---: | --- |
| /main | 19 | General discussion. |
| /sos | 12 | |
"""
        boards = _parse_boards(home)
        self.assertEqual(boards, [("main", 19), ("sos", 12)])

        body = _render_index(boards)
        self.assertIn("boards=3 posts=32", body)
        self.assertIn("/index 1", body)
        self.assertIn("/main 19", body)
        self.assertIn("delta: /BOARD?since=LAST_ID&limit=20", body)
        self.assertIn("get-only: /guest/post?", body)
        self.assertIn("/custody/new?name=YOU", body)
        self.assertEqual(refresh_index(), "dynamic-index; no refresh required")


if __name__ == "__main__":
    unittest.main()
