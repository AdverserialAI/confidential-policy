#!/usr/bin/env python3
"""Tests for policy_release_check.py: python3 tools/test_policy_release_check.py"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).with_name("policy_release_check.py")
GLOBS = "policies/*.json releases/*.json registry/*.json deployments/CURRENT deployments/*/*"
ACTIVE = {"status": "active", "published_at": "2026-11-01T00:00:00.000Z", "trust": {"policy_distribution": "sigstore-rekor", "detached_policy_signature": True}}


class ReleaseCheck(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.repo = Path(self.scratch.name)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "test")

    def tearDown(self):
        self.scratch.cleanup()

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args], check=True, capture_output=True, text=True).stdout.strip()

    def commit(self, files):
        for name, value in files.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value if isinstance(value, str) else json.dumps(value, indent=2) + "\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "change")
        return self.git("rev-parse", "HEAD")

    def check(self, before, after):
        return subprocess.run([sys.executable, str(TOOL), "--before", before, "--after", after, "--globs", GLOBS], cwd=self.repo, capture_output=True, text=True)

    def test_lists_only_changed_signed_files(self):
        first = self.commit({"policies/production.json": ACTIVE, "releases/a.json": {"v": 1}, "README.md": "x"})
        second = self.commit({"releases/b.json": {"v": 2}, "README.md": "y", "schema/s.json": {}})
        result = self.check(first, second)
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "releases/b.json"))
        everything = subprocess.run([sys.executable, str(TOOL), "--before", first, "--after", second, "--globs", GLOBS, "--all"], cwd=self.repo, capture_output=True, text=True)
        self.assertEqual(everything.stdout.split(), ["policies/production.json", "releases/a.json", "releases/b.json"])
        new_branch = self.check("0" * 40, second)
        self.assertEqual(new_branch.stdout.split(), ["policies/production.json", "releases/a.json", "releases/b.json"])

    def test_published_at_must_advance(self):
        first = self.commit({"policies/production.json": ACTIVE})
        same_time = self.commit({"policies/production.json": {**ACTIVE, "model_id": "changed"}})
        self.assertIn("not later than", self.check(first, same_time).stdout)
        later = self.commit({"policies/production.json": {**ACTIVE, "model_id": "changed", "published_at": "2026-11-02T00:00:00.000Z"}})
        self.assertEqual(self.check(first, later).returncode, 0)
        future = self.commit({"policies/production.json": {**ACTIVE, "published_at": "2999-01-01T00:00:00.000Z"}})
        self.assertIn("in the future", self.check(later, future).stdout)

    def test_pre_signing_policy_is_signed_as_it_is_with_a_notice(self):
        first = self.commit({"README.md": "x"})
        unsigned = self.commit({"policies/production.json": {**ACTIVE, "trust": {"policy_distribution": "https-origin", "detached_policy_signature": False}}})
        result = self.check(first, unsigned)
        self.assertEqual(result.returncode, 0)
        self.assertIn("::notice::", result.stdout)
        self.assertEqual(result.stdout.strip().splitlines()[-1], "policies/production.json")

    def test_deployment_files_are_in_scope(self):
        first = self.commit({"README.md": "x"})
        second = self.commit({"deployments/v0.1.0-rc.33/policy.json": {"v": 1}, "deployments/v0.1.0-rc.33/docker-compose.yml": "services: {}\n", "deployments/CURRENT": "v0.1.0-rc.33\n"})
        self.assertEqual(self.check(first, second).stdout.split(), ["deployments/CURRENT", "deployments/v0.1.0-rc.33/docker-compose.yml", "deployments/v0.1.0-rc.33/policy.json"])

    def test_unsafe_file_names_are_refused(self):
        first = self.commit({"README.md": "x"})
        odd = self.commit({"policies/a b;c.json": {}})
        self.assertIn("not safe to sign", self.check(first, odd).stdout)


if __name__ == "__main__":
    unittest.main()
