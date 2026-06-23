import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from rai_scan.config import load_signatures
from rai_scan.scanner import (
    CACHE_MAX_AGE_SECONDS,
    SCHEMA_VERSION,
    _signature_fingerprint,
    get_manifest,
)


class ScannerCacheTests(unittest.TestCase):
    def _write_cache(self, state: Path, include_root: bool) -> dict:
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "scan_time": "2026-06-23T00:00:00+00:00",
            "system": "linux",
            "include_root": include_root,
            "signature_fingerprint": _signature_fingerprint(load_signatures()),
            "total_reclaimable_bytes": 0,
            "possible_ai_related_bytes": 0,
            "agents": [],
            "ai_related": [],
            "orphans": [],
        }
        state.mkdir(parents=True, exist_ok=True)
        (state / "last_scan.json").write_text(json.dumps(manifest))
        return manifest

    def test_fresh_matching_cache_is_used(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            with patch.dict(os.environ, {"RAI_SCAN_HOME": str(state)}):
                manifest = self._write_cache(state, False)
                with patch("rai_scan.scanner.scan_system") as scan:
                    result = get_manifest(include_root=False)
            self.assertEqual(result, manifest)
            scan.assert_not_called()

    def test_cache_scope_must_match(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            with patch.dict(os.environ, {"RAI_SCAN_HOME": str(state)}):
                self._write_cache(state, False)
                with patch(
                    "rai_scan.scanner.scan_system", return_value={"fresh": True}
                ) as scan:
                    result = get_manifest(include_root=True)
            self.assertEqual(result, {"fresh": True})
            scan.assert_called_once_with(True)

    def test_stale_cache_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            with patch.dict(os.environ, {"RAI_SCAN_HOME": str(state)}):
                self._write_cache(state, False)
                cache = state / "last_scan.json"
                old = time.time() - CACHE_MAX_AGE_SECONDS - 1
                os.utime(cache, (old, old))
                with patch(
                    "rai_scan.scanner.scan_system", return_value={"fresh": True}
                ) as scan:
                    result = get_manifest(include_root=False)
            self.assertEqual(result, {"fresh": True})
            scan.assert_called_once_with(False)
