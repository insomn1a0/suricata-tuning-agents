"""Markdown links must resolve to tracked files."""
import unittest

from .helpers import load

links = load("tools/check_links.py", "check_links")
TRACKED = {"README.md", "docs/SAFETY.md", "examples/cards/2025701.md", "wazuh/rules/x.xml"}


class LinksTest(unittest.TestCase):
    def test_resolves_relative_and_dirs(self):
        text = ("[a](docs/SAFETY.md) [b](examples/cards/2025701.md#decision) [c](wazuh/rules) "
                "[d](https://x.org) [e](#top)")
        self.assertEqual(links.broken("README.md", text, TRACKED), [])
        self.assertEqual(links.broken("docs/SAFETY.md", "[r](../README.md) [s](./SAFETY.md)", TRACKED), [])

    def test_untracked_target(self):
        self.assertEqual(links.broken("README.md", "[c](cards/1.md)", TRACKED),
                         ["README.md: link to untracked or missing cards/1.md"])


if __name__ == "__main__":
    unittest.main()
