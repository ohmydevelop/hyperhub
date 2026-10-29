import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "test-dynamic-attach.py"
SPEC = importlib.util.spec_from_file_location("test_dynamic_attach_driver_script", SCRIPT)
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


class TargetStdioCaptureTests(unittest.TestCase):
    def test_cleanup_pending_is_transitional_only_when_the_caller_opts_in(self):
        self.assertTrue(DRIVER.phase_is_terminal_failure("cleanup_pending"))
        self.assertFalse(
            DRIVER.phase_is_terminal_failure(
                "cleanup_pending", transient=["cleanup_pending"]
            )
        )
        self.assertTrue(
            DRIVER.phase_is_terminal_failure("failed", transient=["cleanup_pending"])
        )

    def test_stderr_is_drained_and_reported_without_an_unbounded_copy(self):
        read_fd, write_fd = os.pipe()
        stream = os.fdopen(read_fd, "rb", buffering=0)
        capture = DRIVER.TargetStdioCapture("fixture", stream)
        payload = b"diagnostic\n" * 100_000
        os.write(write_fd, payload)
        os.close(write_fd)
        capture.close()
        stream.close()

        snapshot = capture.snapshot()
        self.assertTrue(snapshot["drain_closed"])
        self.assertEqual(snapshot["stderr_bytes"], len(payload))
        self.assertEqual(len(snapshot["stderr_sha256"]), 64)
        self.assertLessEqual(len(snapshot["stderr_prefix"]), 1024)

    def test_unexpected_stdout_has_separate_bounded_evidence(self):
        read_fd, write_fd = os.pipe()
        stream = os.fdopen(read_fd, "rb", buffering=0)
        capture = DRIVER.TargetStdioCapture("fixture", stream)
        os.close(write_fd)
        capture.record_unexpected_stdout(b"first\n")
        capture.record_unexpected_stdout(b"second\x00")
        capture.close()
        stream.close()

        snapshot = capture.snapshot()
        self.assertEqual(snapshot["stderr_bytes"], 0)
        self.assertEqual(snapshot["unexpected_stdout_bytes"], 13)
        self.assertEqual(snapshot["unexpected_stdout_prefix"], "first\\x0asecond\\x00")
        self.assertEqual(len(snapshot["unexpected_stdout_sha256"]), 64)

    def test_failure_evidence_copies_only_regular_private_manager_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            output = root / "evidence"
            first = home / "runtime" / "attachments" / "first"
            second = home / "runtime" / "attachments" / "second"
            first.mkdir(parents=True)
            second.mkdir()
            output.mkdir()
            (first / "manager.log").write_text("first-stage\n")
            (second / "real.log").write_text("must-not-follow\n")
            (second / "manager.log").symlink_to(second / "real.log")

            copied = DRIVER.copy_manager_logs(home, output)

            self.assertEqual(copied, 1)
            self.assertEqual(
                (output / "manager-diagnostics" / "first" / "manager.log").read_text(),
                "first-stage\n",
            )
            self.assertFalse(
                (output / "manager-diagnostics" / "second" / "manager.log").exists()
            )


if __name__ == "__main__":
    unittest.main()
