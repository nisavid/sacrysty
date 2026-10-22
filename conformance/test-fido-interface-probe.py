#!/usr/bin/env python3
"""Disposable execution-binding controls; not historical age qualification."""

import errno
from contextlib import nullcontext
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import types
import unittest
from unittest import mock

from test_support import external_temporary_directory

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "docs/research/fido-worker-interfaces/evidence"
SPEC = importlib.util.spec_from_file_location("interface_probe", EVIDENCE / "probe.py")
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)
SAFE = b"#!/bin/sh\nprintf verified\n"
OTHER = b"#!/bin/sh\nprintf substituted\n"
SUPPORTED = all(hasattr(os, name) for name in (
    "memfd_create", "MFD_CLOEXEC", "MFD_ALLOW_SEALING", "O_NOFOLLOW",
)) and all(hasattr(fcntl, name) for name in (
    "F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_WRITE", "F_SEAL_GROW",
    "F_SEAL_SHRINK", "F_SEAL_SEAL",
))

# A constructed trace producer exercises main's two branches and receipt only.
# It does not implement the age protocol or authenticate a real plugin.
CONTROL = b'''#!/usr/bin/python3
import json, os, signal, sys, time
sys.stdin.buffer.read()
mode = open("mode").read()
trace = {key: True for key in ("premises", "argv", "identity", "wrap", "extension", "done", "expected")}
def save():
    with open(mode + ".json.tmp", "w") as f:
        json.dump(trace, f)
    os.replace(mode + ".json.tmp", mode + ".json")
def stop(_sig, _frame):
    trace["terminal"] = "eof"
    save()
    sys.exit(0)
if mode == "cancel":
    signal.signal(signal.SIGINT, stop)
    trace["ready"] = True
save()
if mode == "pin":
    sys.exit(1)
while True:
    time.sleep(0.01)
'''


class ProbeTests(unittest.TestCase):
    """Exercise execution identity and receipts with disposable value-free fixtures."""
    def setUp(self):
        """Create an executable fixture outside the checkout and reset probe state."""
        temporary = external_temporary_directory(ROOT, prefix="fido-probe-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "age"
        self.source.write_bytes(SAFE)
        self.source.chmod(0o700)
        probe.children.clear()
        probe.captures.clear()

    def tearDown(self):
        """Reap remaining fixture children and close capture streams."""
        for child in probe.children:
            if child.poll() is None:
                probe.cleanup_group(child)
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream and not stream.closed:
                    stream.close()
        for threads in probe.captures:
            for thread in threads:
                thread.join(1)
        probe.children.clear()
        probe.captures.clear()

    def verify(self, data=SAFE):
        """Admit fixture bytes with a test-only digest and schedule descriptor cleanup."""
        with mock.patch.object(probe, "AGE_SHA", hashlib.sha256(data).hexdigest()):
            fd = probe.verified_age(str(self.source))
        self.addCleanup(os.close, fd)
        return fd

    def launch(self, fd):
        """Require the sealed fixture to execute successfully and emit its marker."""
        child, state, threads = probe.spawn(fd, "identity", {}, str(self.root))
        bounded, rc, out, err = probe.finish(child, state, threads, 2)
        self.assertTrue(bounded)
        self.assertEqual((rc, out, err), (0, b"verified", b""))

    @unittest.skipUnless(SUPPORTED, "Linux file sealing is unavailable")
    def test_swap_execute_restore_both_launches(self):
        """Reject pathname substitution despite restoration around both launches."""
        fd = self.verify()
        original = self.root / "original"
        for _ in range(2):
            self.source.rename(original)
            self.source.write_bytes(OTHER)
            self.source.chmod(0o700)
            self.launch(fd)
            self.source.unlink()
            original.rename(self.source)
            self.assertEqual(hashlib.sha256(self.source.read_bytes()).digest(), hashlib.sha256(SAFE).digest())

    @unittest.skipUnless(SUPPORTED, "Linux file sealing is unavailable")
    def test_inode_and_path_aliases_do_not_change_execution(self):
        """Keep admitted bytes stable across inode writes and pathname alias changes."""
        fd = self.verify()
        alias = self.root / "alias"
        os.link(self.source, alias)
        alias.write_bytes(OTHER)
        self.launch(fd)
        self.source.unlink()
        self.launch(fd)
        self.source.symlink_to(alias)
        self.launch(fd)
        parent = self.root / "ancestor"
        parent.mkdir()
        nested = parent / "age"
        nested.write_bytes(SAFE)
        nested.chmod(0o700)
        self.source = nested
        nested_fd = self.verify()
        parent.rename(self.root / "old-ancestor")
        parent.mkdir()
        nested.write_bytes(OTHER)
        nested.chmod(0o700)
        self.launch(nested_fd)

    @unittest.skipUnless(SUPPORTED, "Linux file sealing is unavailable")
    def test_native_executable_control(self):
        """Execute a native binary through the admitted descriptor."""
        shutil.copyfile("/bin/true", self.source)
        fd = self.verify(self.source.read_bytes())
        result = subprocess.run([f"/proc/self/fd/{fd}"], pass_fds=(fd,), capture_output=True, timeout=2)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"", b""))

    @unittest.skipUnless(SUPPORTED, "Linux file sealing is unavailable")
    def test_snapshot_rejects_writes_shrinkage_and_growth(self):
        """Require kernel seals to reject changes to the admitted object."""
        fd = self.verify()
        for operation in (lambda: os.pwrite(fd, OTHER, 0), lambda: os.ftruncate(fd, 0), lambda: os.ftruncate(fd, len(SAFE) + 1)):
            with self.subTest(operation=operation), self.assertRaises(OSError) as raised:
                operation()
            self.assertEqual(raised.exception.errno, errno.EPERM)
        self.launch(fd)

    @unittest.skipUnless(SUPPORTED, "Linux file sealing is unavailable")
    def test_invalid_sources_never_launch(self):
        """Reject mismatched, empty, nonexecutable, oversized, and nonregular inputs."""
        with mock.patch.object(probe.subprocess, "Popen") as launch:
            for data, mode in ((OTHER, 0o700), (b"", 0o700), (SAFE, 0o600)):
                self.source.write_bytes(data)
                self.source.chmod(mode)
                with self.subTest(data=data, mode=mode), self.assertRaises(probe.Fail):
                    self.verify()
            self.source.write_bytes(SAFE)
            self.source.chmod(0o700)
            with mock.patch.object(probe, "AGE_SIZE_CAP", len(SAFE) - 1), self.assertRaises(probe.Fail):
                self.verify()
            self.source.unlink()
            for kind in ("fifo", "symlink", "directory"):
                if kind == "fifo":
                    os.mkfifo(self.source, 0o700)
                elif kind == "symlink":
                    self.source.symlink_to("/bin/true")
                else:
                    self.source.mkdir()
                with self.subTest(kind=kind), self.assertRaises(probe.Fail):
                    self.verify()
                if kind == "directory":
                    self.source.rmdir()
                else:
                    self.source.unlink()
            launch.assert_not_called()

    @unittest.skipUnless(SUPPORTED, "Linux file sealing is unavailable")
    def test_copy_races_are_digest_and_size_checked(self):
        """Reject source mutation after stat through digest and actual byte limits."""
        read = os.read
        for mutation in (OTHER[:len(SAFE)], SAFE * 2):
            self.source.write_bytes(SAFE)
            first = True
            def racing_read(fd, size):
                """Mutate the source after its initial stat and before copying bytes."""
                nonlocal first
                if first:
                    first = False
                    self.source.write_bytes(mutation)
                return read(fd, size)
            with self.subTest(mutation=mutation), mock.patch.object(probe.os, "read", side_effect=racing_read), mock.patch.object(probe, "AGE_SIZE_CAP", len(SAFE)), self.assertRaises(probe.Fail):
                self.verify()

    @unittest.skipUnless(SUPPORTED, "Linux file sealing is unavailable")
    def test_partial_writes_preserve_verified_bytes(self):
        """Finish short writes without losing or duplicating copied bytes."""
        write = os.write
        with mock.patch.object(probe.os, "write", side_effect=lambda fd, data: write(fd, data[:3])):
            fd = self.verify()
        self.launch(fd)

    @unittest.skipUnless(SUPPORTED, "Linux file sealing is unavailable")
    def test_zero_write_fails_without_looping(self):
        """Reject a copy that cannot make forward progress."""
        with mock.patch.object(probe.os, "write", return_value=0), self.assertRaisesRegex(probe.Fail, "age_execution_binding"):
            self.verify()

    @unittest.skipUnless(SUPPORTED, "Linux file sealing is unavailable")
    def test_admission_failures_close_source_and_snapshot(self):
        """Close every allocated descriptor when preparation fails."""
        open_source, create_snapshot = os.open, os.memfd_create
        for owner, name in ((probe.os, "read"), (probe.os, "write"), (probe.os, "fchmod"), (probe.fcntl, "fcntl"), (probe, "hash_age")):
            allocated = []
            def capture(call):
                """Wrap descriptor allocation so failure cleanup can be observed."""
                def wrapper(*args, **kwargs):
                    """Record each allocated descriptor without changing allocation behavior."""
                    fd = call(*args, **kwargs)
                    allocated.append(fd)
                    return fd
                return wrapper
            with self.subTest(name=name), mock.patch.object(probe.os, "open", side_effect=capture(open_source)), mock.patch.object(probe.os, "memfd_create", side_effect=capture(create_snapshot)), mock.patch.object(owner, name, side_effect=OSError(errno.EIO, "injected")), self.assertRaises(probe.Fail):
                self.verify()
            self.assertEqual(len(allocated), 2)
            for fd in allocated:
                with self.assertRaises(OSError) as raised:
                    os.fstat(fd)
                self.assertEqual(raised.exception.errno, errno.EBADF)

    @unittest.skipUnless(SUPPORTED, "Linux file sealing is unavailable")
    def test_incomplete_seals_fail_closed(self):
        """Reject a snapshot whose seal readback omits required protections."""
        fcntl_call = fcntl.fcntl
        def incomplete(fd, command, *args):
            """Simulate a kernel readback missing the required seals."""
            if command == fcntl.F_GET_SEALS:
                return 0
            return fcntl_call(fd, command, *args)
        with mock.patch.object(probe.fcntl, "fcntl", side_effect=incomplete), self.assertRaisesRegex(probe.Fail, "age_execution_binding"):
            self.verify()

    @unittest.skipUnless(SUPPORTED, "Linux file sealing is unavailable")
    def test_descriptor_execution_failure_has_no_path_fallback(self):
        """Attempt only the descriptor executable when process creation fails."""
        fd = self.verify()
        with mock.patch.object(probe.subprocess, "Popen", side_effect=FileNotFoundError) as launch, self.assertRaises(FileNotFoundError):
            probe.spawn(fd, "identity", {}, str(self.root))
        launch.assert_called_once()
        self.assertEqual(launch.call_args.args[0][0], f"/proc/self/fd/{fd}")
        self.assertEqual(launch.call_args.kwargs["pass_fds"], (fd,))

    def run_main(self, output, **patches):
        """Invoke the CLI routine while restoring process-wide test state."""
        with mock.patch.object(sys, "argv", [str(EVIDENCE / "probe.py"), str(self.source), str(output)]), (mock.patch.multiple(probe, **patches) if patches else nullcontext()):
            old_umask = os.umask(0o077)
            old_alarm = signal.getsignal(signal.SIGALRM)
            try:
                return probe.main()
            finally:
                os.umask(old_umask)
                signal.signal(signal.SIGALRM, old_alarm)

    @unittest.skipUnless(SUPPORTED, "Linux file sealing is unavailable")
    def test_main_two_launches_and_v3_receipt(self):
        """Bind both complete branches to one descriptor despite source overwrites."""
        self.source.write_bytes(CONTROL)
        output = self.root / "output"
        descriptors = []
        spawn = probe.spawn
        def substitute(fd, *args):
            """Overwrite the source before each actual descriptor launch."""
            descriptors.append(fd)
            self.source.write_bytes(OTHER)
            return spawn(fd, *args)
        self.assertEqual(self.run_main(output, AGE_SHA=hashlib.sha256(CONTROL).hexdigest(), spawn=substitute), 0)
        self.assertEqual(len(descriptors), 2)
        self.assertEqual(descriptors[0], descriptors[1])
        with self.assertRaises(OSError):
            os.fstat(descriptors[0])
        receipt = json.loads((output / "observations.json").read_text())
        self.assertEqual(receipt["schema"], "sacrysty-age-interface-probe-v3")
        self.assertEqual(receipt["probe_status"], "complete")
        self.assertEqual(receipt["age_execution"], {"binding": "sealed_memfd", "sha256": hashlib.sha256(CONTROL).hexdigest()})
        self.assertTrue(all(receipt["premises"].values()))
        self.assertTrue(all(receipt["cleanup"].values()))
        self.assertEqual([p.name for p in output.iterdir()], ["observations.json"])

    @unittest.skipUnless(SUPPORTED, "Linux file sealing is unavailable")
    def test_main_launch_error_closes_snapshot_and_cleans_fixtures(self):
        """Retain an error receipt and release resources after denied execution."""
        output = self.root / "output"
        descriptors = []
        def deny(fd, *args):
            """Capture the admitted descriptor before simulating an execution denial."""
            descriptors.append(fd)
            raise PermissionError("descriptor exec denied")
        self.assertEqual(self.run_main(output, AGE_SHA=hashlib.sha256(SAFE).hexdigest(), spawn=deny), 1)
        with self.assertRaises(OSError):
            os.fstat(descriptors[0])
        receipt = json.loads((output / "observations.json").read_text())
        self.assertEqual(receipt["probe_status"], "error")
        self.assertTrue(all(receipt["cleanup"].values()))
        self.assertEqual([p.name for p in output.iterdir()], ["observations.json"])

    def test_missing_sealing_support_rejects_before_open(self):
        """Fail before source admission when platform sealing APIs are absent."""
        with mock.patch.object(probe, "fcntl", types.SimpleNamespace()), mock.patch.object(probe.os, "open") as opened, self.assertRaisesRegex(probe.Fail, "age_execution_platform"):
            probe.verified_age(str(self.source))
        opened.assert_not_called()

    def test_invalid_cli_arguments(self):
        """Preserve absolute-input and fresh-output CLI rejection behavior."""
        with mock.patch.object(sys, "argv", ["probe.py", "relative", str(self.root / "out")]):
            self.assertEqual(probe.main(), 64)
        self.assertEqual(self.run_main(self.root), 65)

    def test_current_inventory_and_historical_receipts(self):
        """Match current inventory bytes and preserve the original receipt digests."""
        manifest = json.loads((EVIDENCE.parent / "evidence-manifest.json").read_text())
        for item in manifest["files"]:
            data = (EVIDENCE.parent / item["path"]).read_bytes()
            self.assertEqual(len(data), item["bytes"])
            self.assertEqual(hashlib.sha256(data).hexdigest(), item["sha256"])
        for name, digest in (
            ("interface-execution-receipt.json", "f1358999033aca2764eb1db2e5c937feb70a07b028bb9c001419b22e6540a733"),
            ("observations.json", "186a6c597d1e41122e86c7781f73b19a53f1a228f45636600833306fd8ba7044"),
        ):
            self.assertEqual(hashlib.sha256((EVIDENCE / name).read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
