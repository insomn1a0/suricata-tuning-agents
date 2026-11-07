"""ET Open fetch without the network: license range, selection, refusal - on a synthetic in-memory archive."""
import io
import tarfile
import unittest

from .helpers import load

try:
    fetch = load("tools/fetch_et_rules.py", "fetch_et_rules")
except ModuleNotFoundError as e:  # PyYAML missing: `make venv`
    raise unittest.SkipTest(f"fetch needs {e.name}") from e

LICENSE = ("#  Rules with sids 2000000 through 2799999 are from Emerging Threats and are covered under the BSD "
           "License\n")
RULES = ('alert tcp any any -> $HOME_NET 445 (msg:"x"; sid:2025701; rev:2; metadata:signature_severity Minor;)\n'
         '# alert tcp any any -> any any (msg:"old"; sid:2025709; rev:1;)\n')


def archive(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class FetchEt(unittest.TestCase):
    def test_members_and_selection(self):
        files = fetch.members(archive({"rules/LICENSE": LICENSE, "rules/emerging-info.rules": RULES,
                                       "../evil.rules": "alert", "rules/sub/x.rules": "alert"}))
        self.assertEqual(sorted(files), ["rules/LICENSE", "rules/emerging-info.rules"])  # nothing outside rules/
        found = fetch.select(files.values(), {2025701, 2025709})
        self.assertEqual(list(found), [2025701])  # the commented-out rule does not count
        self.assertTrue(fetch.BSD_RANGE.search(LICENSE))


if __name__ == "__main__":
    unittest.main()
