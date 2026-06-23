import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from rai_scan.probes import ai_related_probe, daemon_probe, fs_probe, shell_probe


class ProbeTests(unittest.TestCase):
    def test_filesystem_and_shell_probes(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            binary = home / ".local/bin/demo"
            binary.parent.mkdir(parents=True)
            binary.write_text("#!/bin/sh\n")
            config = home / ".config/demo"
            config.mkdir(parents=True)
            (home / ".bashrc").write_text("# Added by demo\nexport OTHER=1\n")
            signatures = {
                "agents": {
                    "demo": {
                        "binaries": ["demo"],
                        "config_dirs": [".config/demo"],
                        "cache_dirs": [],
                        "shell_patterns": ["Added by demo"],
                    }
                }
            }
            with patch("rai_scan.probes.fs_probe.Path.home", return_value=home), patch(
                "rai_scan.probes.shell_probe.Path.home", return_value=home
            ), patch("rai_scan.probes.fs_probe.shutil.which", return_value=None):
                artifacts = fs_probe.scan(signatures)
                lines = shell_probe.scan(signatures)
            self.assertEqual({item.type for item in artifacts}, {"binary", "config"})
            self.assertEqual(lines[0].line_number, 1)
            self.assertEqual(lines[0].agent_hint, "demo")

    def test_private_binary_path_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            binary = home / ".demo/bin/demo"
            binary.parent.mkdir(parents=True)
            binary.write_text("#!/bin/sh\n")
            signatures = {
                "agents": {
                    "demo": {
                        "binaries": ["demo"],
                        "binary_paths": [".demo/bin/demo"],
                        "config_dirs": [],
                        "cache_dirs": [],
                    }
                }
            }
            with patch("rai_scan.probes.fs_probe.Path.home", return_value=home), patch(
                "rai_scan.probes.fs_probe.shutil.which", return_value=None
            ):
                artifacts = fs_probe.scan(signatures)
            self.assertEqual([item.path for item in artifacts], [str(binary)])

    def test_unknown_model_store_is_reported_as_ai_related(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            model = home / ".semantic_search/models/demo/model.safetensors"
            model.parent.mkdir(parents=True)
            model.write_bytes(b"model")
            with patch("rai_scan.probes.ai_related_probe.Path.home", return_value=home):
                artifacts = ai_related_probe.scan({"agents": {}}, [])
            self.assertEqual(len(artifacts), 1)
            self.assertEqual(artifacts[0].path, str(home / ".semantic_search"))
            self.assertTrue(artifacts[0].agent_hint.startswith("name:"))

    def test_known_agent_path_is_not_duplicated_as_ai_related(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            path = home / ".config/ai-agent"
            path.mkdir(parents=True)
            signatures = {
                "agents": {
                    "demo": {
                        "config_dirs": [".config/ai-agent"],
                        "cache_dirs": [],
                        "binary_paths": [],
                    }
                }
            }
            with patch("rai_scan.probes.ai_related_probe.Path.home", return_value=home):
                artifacts = ai_related_probe.scan(signatures, [])
            self.assertEqual(artifacts, [])

    def test_extension_glob_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            extension = home / ".vscode/extensions/example.agent-1.2.3"
            extension.mkdir(parents=True)
            signatures = {
                "agents": {
                    "demo": {
                        "binaries": [],
                        "config_dirs": [],
                        "cache_dirs": [],
                        "config_globs": [".vscode/extensions/example.agent-*"],
                    }
                }
            }
            with patch("rai_scan.probes.fs_probe.Path.home", return_value=home):
                artifacts = fs_probe.scan(signatures)
            self.assertEqual(len(artifacts), 1)
            self.assertEqual(artifacts[0].path, str(extension))

    def test_short_daemon_pattern_uses_token_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            units = home / ".config/systemd/user"
            units.mkdir(parents=True)
            (units / "fix.service").write_text("[Service]\n")
            (units / "ix.service").write_text("[Service]\n")
            signatures = {"agents": {"ix": {"systemd_patterns": ["ix"]}}}
            with patch("rai_scan.probes.daemon_probe.Path.home", return_value=home), patch(
                "rai_scan.probes.daemon_probe.shutil.which",
                return_value="/usr/bin/systemctl",
            ), patch(
                "rai_scan.probes.daemon_probe.subprocess.run",
                side_effect=[
                    Mock(returncode=0),
                    Mock(returncode=1),
                ],
            ):
                result = daemon_probe.scan(signatures)
            self.assertEqual([item.name for item in result], ["ix.service"])
            self.assertTrue(result[0].enabled)
            self.assertFalse(result[0].active)

    def test_pip_probe_ignores_non_object_rows(self):
        signatures = {"agents": {"demo": {"pip_packages": ["demo"]}}}
        with patch(
            "rai_scan.probes.pkg_probe.shutil.which",
            side_effect=lambda value: "/env/bin/pip" if value == "pip" else None,
        ), patch(
            "rai_scan.probes.pkg_probe._run",
            return_value='[1, "demo", {"name": "demo", "version": "1.0"}]',
        ):
            from rai_scan.probes import pkg_probe

            result = pkg_probe.scan(signatures)
        self.assertEqual([(item.name, item.version) for item in result], [("demo", "1.0")])


if __name__ == "__main__":
    unittest.main()
