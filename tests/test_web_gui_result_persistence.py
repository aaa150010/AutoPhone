from __future__ import annotations

import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from tests.web_gui_test_runtime import RecoveredWebGuiImport


class WebGuiResultPersistenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.previous_data_dir = os.environ.get("GPTPHONE_DATA_DIR")
        os.environ["GPTPHONE_DATA_DIR"] = cls.tempdir.name
        cls.web_gui_import = RecoveredWebGuiImport(Path(__file__).resolve().parents[1])
        cls.module = cls.web_gui_import.load()

    @classmethod
    def tearDownClass(cls):
        if cls.previous_data_dir is None:
            os.environ.pop("GPTPHONE_DATA_DIR", None)
        else:
            os.environ["GPTPHONE_DATA_DIR"] = cls.previous_data_dir
        cls.web_gui_import.cleanup()
        cls.tempdir.cleanup()

    def test_batch_manifest_is_not_marked_when_metadata_write_fails(self):
        module = self.module
        original_persist = module._ORIGINAL_PERSIST_RESULT
        original_apply = module._result_persistence_runtime_ext.apply_result_json_metadata
        original_manifest = module._RUN_BATCH_MANIFEST
        manifest_calls = []
        try:
            module._ORIGINAL_PERSIST_RESULT = lambda *_args, **_kwargs: "persisted"
            module._result_persistence_runtime_ext.apply_result_json_metadata = (
                lambda *_args, **_kwargs: False
            )
            module._RUN_BATCH_MANIFEST = SimpleNamespace(
                mark_persisted=lambda *args: manifest_calls.append(args)
            )
            returned = module._patched_persist_result(
                SimpleNamespace(data_dir=self.tempdir.name),
                {
                    "batch_id": "batch-metadata-failed",
                    "batch_started_at": 123,
                },
                "task-metadata-failed",
                SimpleNamespace(email="masked@example.test"),
                {},
                status="success",
            )
        finally:
            module._ORIGINAL_PERSIST_RESULT = original_persist
            module._result_persistence_runtime_ext.apply_result_json_metadata = original_apply
            module._RUN_BATCH_MANIFEST = original_manifest
            module._TASK_PROGRESS.reset()

        self.assertEqual(returned, "persisted")
        self.assertEqual(manifest_calls, [])


if __name__ == "__main__":
    unittest.main()
