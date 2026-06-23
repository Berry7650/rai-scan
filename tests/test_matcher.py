import unittest

from rai_scan.classifier.matcher import classify
from rai_scan.models import Artifact, Package, unique_non_overlapping


class MatcherTests(unittest.TestCase):
    def test_classify_matches_artifacts_and_packages(self):
        signatures = {
            "agents": {
                "demo": {
                    "display_name": "Demo",
                    "pip_packages": ["demo-pkg"],
                }
            }
        }
        agents, orphans = classify(
            signatures,
            [Artifact("/tmp/demo", "binary", 12, agent_hint="demo")],
            [Package("pip", "demo-pkg", "1.2.3")],
            [],
            [],
        )
        self.assertFalse(orphans)
        self.assertEqual(agents[0].id, "demo")
        self.assertEqual(agents[0].version_detected, "1.2.3")
        self.assertEqual(agents[0].total_bytes, 12)
        self.assertEqual(agents[0].confidence, "high")

    def test_unmatched_artifact_is_orphan(self):
        agents, orphans = classify(
            {"agents": {}}, [Artifact("/tmp/x", "broken_symlink")], [], [], []
        )
        self.assertFalse(agents)
        self.assertEqual(len(orphans), 1)

    def test_nested_artifacts_are_not_double_counted(self):
        signatures = {"agents": {"demo": {"display_name": "Demo"}}}
        agents, _ = classify(
            signatures,
            [
                Artifact("/tmp/demo", "config", 100, agent_hint="demo"),
                Artifact("/tmp/demo/cache", "cache", 80, agent_hint="demo"),
            ],
            [],
            [],
            [],
        )
        self.assertEqual(agents[0].total_bytes, 100)


class UniqueNonOverlappingTests(unittest.TestCase):
    def test_parent_child_dedup(self):
        result = unique_non_overlapping([
            "/tmp/demo",
            "/tmp/demo/cache",
            "/tmp/demo/cache/models",
        ])
        self.assertEqual(result, ["/tmp/demo"])

    def test_unrelated_paths_kept(self):
        result = unique_non_overlapping(["/tmp/a", "/tmp/b", "/tmp/c"])
        self.assertEqual(len(result), 3)

    def test_empty_input(self):
        self.assertEqual(unique_non_overlapping([]), [])

    def test_same_path_not_duplicated(self):
        result = unique_non_overlapping(["/tmp/x", "/tmp/x"])
        self.assertEqual(result, ["/tmp/x"])


if __name__ == "__main__":
    unittest.main()
