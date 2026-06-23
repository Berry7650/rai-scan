import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from rai_scan.removal.engine import _revalidate_paths, _uninstall, preview, remove_agents
from rai_scan.removal.rollback import append_record, rollback_last


class RemovalTests(unittest.TestCase):
    def test_remove_and_rollback_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            state = root / "state"
            home.mkdir()
            artifact = home / ".config/demo/settings.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("{}")
            agent = {
                "id": "demo",
                "display_name": "Demo",
                "total_bytes": 2,
                "artifacts": [{"path": str(artifact), "type": "config", "size_bytes": 2}],
                "packages": [],
                "shell_lines": [],
                "daemons": [],
            }
            with patch("rai_scan.removal.engine.Path.home", return_value=home), patch.dict(
                os.environ, {"RAI_SCAN_HOME": str(state)}
            ):
                record, errors = remove_agents([agent])
                self.assertFalse(errors)
                self.assertFalse(artifact.exists())
                self.assertTrue(record["files_moved_to_trash"])
                self.assertEqual(record["state"], "complete")
                restored = rollback_last()
            self.assertEqual(restored["agents_removed"], ["demo"])
            self.assertEqual(artifact.read_text(), "{}")

    def test_write_ahead_journal_recovers_move_followed_by_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            state = root / "state"
            home.mkdir()
            artifact = home / ".demo"
            artifact.write_text("recover me")
            agent = {
                "id": "demo",
                "display_name": "Demo",
                "total_bytes": 10,
                "artifacts": [{"path": str(artifact), "type": "config", "size_bytes": 10}],
                "packages": [],
                "shell_lines": [],
                "daemons": [],
            }

            real_move = os.rename

            def move_then_crash(source, destination):
                real_move(source, destination)
                raise RuntimeError("simulated process failure")

            with patch("rai_scan.removal.engine.Path.home", return_value=home), patch.dict(
                os.environ, {"RAI_SCAN_HOME": str(state)}
            ), patch("rai_scan.removal.engine.os.rename", side_effect=move_then_crash):
                record, errors = remove_agents([agent])

            self.assertEqual(record["state"], "partial")
            self.assertTrue(errors)
            self.assertFalse(artifact.exists())
            with patch("rai_scan.removal.rollback.Path.home", return_value=home), patch.dict(
                os.environ, {"RAI_SCAN_HOME": str(state)}
            ):
                restored = rollback_last()
            self.assertEqual(restored["state"], "rolled_back")
            self.assertEqual(artifact.read_text(), "recover me")

    def test_revalidate_paths_catches_missing(self):
        agent = {
            "id": "demo",
            "artifacts": [{"path": "/nonexistent/path/file.txt", "type": "config"}],
        }
        errors = _revalidate_paths(agent)
        self.assertEqual(len(errors), 1)
        self.assertIn("no longer exists", errors[0])

    def test_revalidate_paths_passes_existing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "file.txt"
            path.write_text("x")
            agent = {
                "id": "demo",
                "artifacts": [{"path": str(path), "type": "config"}],
            }
            errors = _revalidate_paths(agent)
            self.assertEqual(errors, [])

    def test_preview_includes_daemon_scope(self):
        agent = {
            "display_name": "Demo",
            "artifacts": [],
            "packages": [],
            "shell_lines": [],
            "daemons": [
                {"type": "systemd", "name": "demo.service", "scope": "system"},
                {"type": "systemd", "name": "demo-user.service", "scope": "user"},
            ],
        }
        text = preview([agent])
        self.assertIn("system systemd unit demo.service", text)
        self.assertIn("disable systemd unit demo-user.service", text)


class PackageExecutableTests(unittest.TestCase):
    def test_package_records_executable(self):
        from rai_scan.models import Package
        pkg = Package("pip", "demo", "1.0", executable="/usr/bin/pip3")
        self.assertEqual(pkg.executable, "/usr/bin/pip3")

    def test_package_executable_optional(self):
        from rai_scan.models import Package
        pkg = Package("npm", "demo", "1.0")
        self.assertIsNone(pkg.executable)

    @patch("rai_scan.removal.engine.subprocess.run")
    def test_pip_uninstall_uses_pip_cli_directly(self, run):
        run.return_value = Mock(returncode=0, stderr="")
        _uninstall({"manager": "pip", "name": "demo", "executable": "/env/bin/pip"})
        command = run.call_args.args[0]
        self.assertEqual(command, ["/env/bin/pip", "uninstall", "-y", "demo"])

    def test_system_package_requires_root_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            agent = {
                "id": "demo",
                "display_name": "Demo",
                "total_bytes": 0,
                "artifacts": [],
                "packages": [
                    {
                        "manager": "npm",
                        "name": "demo",
                        "version": "1.0",
                        "scope": "system",
                    }
                ],
                "shell_lines": [],
                "daemons": [],
            }
            with patch.dict(os.environ, {"RAI_SCAN_HOME": str(state)}), patch(
                "rai_scan.removal.engine.subprocess.run"
            ) as run:
                record, errors = remove_agents([agent], include_root=False)
            self.assertEqual(record["state"], "partial")
            self.assertIn("without --root", errors[0])
            run.assert_not_called()

    def test_root_execution_is_refused(self):
        with patch("rai_scan.safety.os.geteuid", return_value=0):
            with self.assertRaisesRegex(PermissionError, "running as root"):
                remove_agents([])


class RollbackExternalOperationsTests(unittest.TestCase):
    @patch("rai_scan.removal.rollback.subprocess.run")
    def test_rollback_reinstalls_packages_and_reenables_daemons(self, run):
        run.return_value = Mock(returncode=0, stderr="")
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            record = {
                "session_id": "session-1",
                "state": "complete",
                "files_moved_to_trash": [],
                "shell_lines_commented": [],
                "daemons_trashed": [],
                "packages_uninstalled": [
                    {
                        "manager": "pip",
                        "name": "demo",
                        "version": "1.2.3",
                        "executable": "/env/bin/pip",
                    }
                ],
                "daemons_disabled": [
                    {
                        "type": "systemd",
                        "name": "demo.service",
                        "scope": "user",
                        "enabled": True,
                        "active": True,
                    }
                ],
            }
            with patch.dict(os.environ, {"RAI_SCAN_HOME": str(state)}):
                append_record(record)
                restored = rollback_last()

        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn(["/env/bin/pip", "install", "demo==1.2.3"], commands)
        self.assertIn(
            ["systemctl", "--user", "enable", "--now", "demo.service"], commands
        )
        self.assertEqual(restored["state"], "rolled_back")

    def test_same_session_cannot_be_rolled_back_twice(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            record = {
                "session_id": "session-1",
                "state": "complete",
                "files_moved_to_trash": [],
                "shell_lines_commented": [],
                "daemons_trashed": [],
                "packages_uninstalled": [],
                "daemons_disabled": [],
            }
            with patch.dict(os.environ, {"RAI_SCAN_HOME": str(state)}):
                append_record(record)
                rollback_last()
                with self.assertRaisesRegex(RuntimeError, "already been rolled back"):
                    rollback_last()

    @patch("rai_scan.removal.rollback.subprocess.run")
    def test_partial_retry_does_not_repeat_successful_package_restore(self, run):
        daemon_attempts = 0

        def result(command, **_kwargs):
            nonlocal daemon_attempts
            if command[0] == "systemctl":
                daemon_attempts += 1
                if daemon_attempts == 1:
                    return Mock(returncode=1, stderr="service unavailable")
            return Mock(returncode=0, stderr="")

        run.side_effect = result
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            record = {
                "session_id": "session-1",
                "state": "complete",
                "files_moved_to_trash": [],
                "shell_lines_commented": [],
                "daemons_trashed": [],
                "packages_uninstalled": [
                    {
                        "manager": "pip",
                        "name": "demo",
                        "version": "1.2.3",
                        "executable": "/env/bin/pip",
                    }
                ],
                "daemons_disabled": [
                    {
                        "type": "systemd",
                        "name": "demo.service",
                        "scope": "user",
                        "enabled": True,
                        "active": True,
                    }
                ],
            }
            with patch.dict(os.environ, {"RAI_SCAN_HOME": str(state)}):
                append_record(record)
                first = rollback_last()
                second = rollback_last()

        package_commands = [
            call.args[0] for call in run.call_args_list if call.args[0][0] == "/env/bin/pip"
        ]
        self.assertEqual(first["state"], "rollback_partial")
        self.assertEqual(second["state"], "rolled_back")
        self.assertEqual(len(package_commands), 1)

    @patch("rai_scan.removal.rollback.subprocess.run")
    def test_rollback_restores_disabled_stopped_daemon_without_starting(self, run):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            record = {
                "session_id": "session-1",
                "state": "complete",
                "files_moved_to_trash": [],
                "shell_lines_commented": [],
                "daemons_trashed": [],
                "packages_uninstalled": [],
                "daemons_disabled": [
                    {
                        "type": "systemd",
                        "name": "demo.service",
                        "scope": "user",
                        "enabled": False,
                        "active": False,
                    }
                ],
            }
            with patch.dict(os.environ, {"RAI_SCAN_HOME": str(state)}):
                append_record(record)
                restored = rollback_last()
        self.assertEqual(restored["state"], "rolled_back")
        run.assert_not_called()

    @patch("rai_scan.removal.rollback.subprocess.run")
    def test_planned_operations_are_not_replayed(self, run):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            record = {
                "session_id": "session-1",
                "state": "partial",
                "files_moved_to_trash": [],
                "shell_lines_commented": [],
                "daemons_trashed": [],
                "packages_uninstalled": [
                    {
                        "manager": "pip",
                        "name": "demo",
                        "version": "1.0",
                        "journal_state": "planned",
                    }
                ],
                "daemons_disabled": [
                    {
                        "type": "systemd",
                        "name": "demo.service",
                        "scope": "user",
                        "journal_state": "planned",
                    }
                ],
            }
            with patch.dict(os.environ, {"RAI_SCAN_HOME": str(state)}):
                append_record(record)
                restored = rollback_last()
        self.assertEqual(restored["state"], "rolled_back")
        run.assert_not_called()

    def test_changed_shell_line_becomes_partial_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            state = root / "state"
            home.mkdir()
            shell = home / ".bashrc"
            shell.write_text("# rai-scan disabled 2026-01-01: original\n")
            record = {
                "session_id": "session-1",
                "state": "complete",
                "include_root": False,
                "files_moved_to_trash": [],
                "shell_lines_commented": [
                    {"file": str(shell), "line_number": 1, "content": "different"}
                ],
                "daemons_trashed": [],
                "packages_uninstalled": [],
                "daemons_disabled": [],
            }
            with patch("rai_scan.removal.rollback.Path.home", return_value=home), patch.dict(
                os.environ, {"RAI_SCAN_HOME": str(state)}
            ):
                append_record(record)
                restored = rollback_last()
        self.assertEqual(restored["state"], "rollback_partial")
        self.assertIn("shell line changed", restored["rollback_errors"][0])


class DaemonScopeTests(unittest.TestCase):
    def test_daemon_entry_has_scope(self):
        from rai_scan.models import DaemonEntry
        entry = DaemonEntry("systemd", "test.service", "/tmp/test", scope="system")
        self.assertEqual(entry.scope, "system")

    def test_daemon_entry_default_scope(self):
        from rai_scan.models import DaemonEntry
        entry = DaemonEntry("systemd", "test.service", "/tmp/test")
        self.assertEqual(entry.scope, "user")


class ConfigMergeTests(unittest.TestCase):
    def test_user_signatures_merge_with_bundled(self):
        from rai_scan.config import load_signatures
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            user_sigs = {
                "version": "1.0.0",
                "agents": {
                    "custom_agent": {
                        "display_name": "Custom Agent",
                        "binaries": ["custom-agent"],
                        "pip_packages": [],
                        "npm_packages": [],
                        "cargo_packages": [],
                        "config_dirs": [],
                        "cache_dirs": [],
                        "config_globs": [],
                        "cache_globs": [],
                        "shell_patterns": ["custom-agent"],
                        "systemd_patterns": [],
                    }
                },
            }
            sig_path = state / "signatures.json"
            sig_path.write_text(json.dumps(user_sigs))
            with patch.dict(os.environ, {"RAI_SCAN_HOME": str(state)}):
                data = load_signatures()
            self.assertIn("custom_agent", data["agents"])
            self.assertGreaterEqual(len(data["agents"]), 2)

    def test_invalid_user_signatures_fall_back(self):
        from rai_scan.config import load_signatures
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            sig_path = state / "signatures.json"
            sig_path.write_text("not valid json {{{")
            with patch.dict(os.environ, {"RAI_SCAN_HOME": str(state)}):
                data = load_signatures()
            self.assertIn("agents", data)
            self.assertGreaterEqual(len(data["agents"]), 1)


if __name__ == "__main__":
    unittest.main()
