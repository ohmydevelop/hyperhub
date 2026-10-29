"""Source dependency contract tests; no network, compiler or Frida process needed."""
import difflib
import hashlib
import io
import json
import tarfile
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts/native-deps"))
import bootstrap
import build_glib
import build_helpers
import common
import compiler_configuration
import devkit_headers
import verify


class PairTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="frida sdk contract ")
        self.root = Path(self.temporary.name)
        self.gum, self.core = self.root / "gum", self.root / "core"
        for name, root in (("gum", self.gum), ("core", self.core)):
            root.mkdir()
            (root / f"frida-{name}.h").write_text("same public version 17.17.0")
            (root / f"libfrida-{name}.a").write_bytes(name.encode())
        self.recipe = common.recipe_identity()
        common.write_pair_receipt(self.gum, self.core, "x86_64", self.recipe)

    def tearDown(self):
        self.temporary.cleanup()

    def check(self):
        return common.verify_pair(self.gum, self.core, "x86_64", self.recipe)

    def test_pair_round_trip_and_relocation(self):
        self.check()
        relocated = self.root / "relocated"
        self.gum.rename(relocated)
        common.verify_pair(relocated, self.core, "x86_64", self.recipe)

    def test_any_same_version_library_or_header_change_is_rejected(self):
        for root, filename in ((self.gum, "libfrida-gum.a"), (self.core, "libfrida-core.a"),
                               (self.gum, "frida-gum.h"), (self.core, "frida-core.h")):
            path = root / filename
            original = path.read_bytes()
            path.write_bytes(b"x" + original[1:])
            with self.assertRaises(ValueError):
                self.check()
            path.write_bytes(original)
        self.check()

    def test_architecture_recipe_and_receipts_must_match(self):
        with self.assertRaises(ValueError):
            common.verify_pair(self.gum, self.core, "aarch64", self.recipe)
        with self.assertRaises(ValueError):
            common.verify_pair(self.gum, self.core, "x86_64", "f" * 64)
        receipt = self.core / "hyperhub-frida-sdk.json"
        value = json.loads(receipt.read_text())
        value["artifacts"]["core/frida-core.h"] = "f" * 64
        receipt.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            self.check()

    def test_unrecorded_linker_input_and_missing_file_are_rejected(self):
        shadow = self.core / "libfrida-core.so"
        shadow.write_bytes(b"unidentified dynamic library")
        with self.assertRaises(ValueError):
            self.check()
        shadow.unlink()
        (self.core / "frida-core.h").unlink()
        with self.assertRaises(ValueError):
            self.check()

    def test_symlink_artifact_is_rejected(self):
        if not hasattr(Path, "symlink_to"):
            self.skipTest("symlinks unavailable")
        path = self.gum / "libfrida-gum.a"
        original = self.root / "outside.a"
        path.rename(original)
        try:
            path.symlink_to(original)
        except OSError:
            self.skipTest("symlink privilege unavailable")
        with self.assertRaises(ValueError):
            self.check()


class SourceInputTests(unittest.TestCase):
    def test_patch_digests_are_fixed_to_reviewed_source_changes(self):
        for name, expected in common.MANIFEST["patches"].items():
            self.assertEqual(common.sha256(common.VENDOR / "patches" / name), expected)
        self.assertEqual(common.MANIFEST["dependencies_version"], "20260717")
        self.assertEqual(set(common.MANIFEST["toolchains"]), {"x86_64", "x86", "arm64"})

    def test_recovery_diagnostics_never_write_to_the_target_stdio(self):
        patch = (common.VENDOR / "patches" / "child-agent-lifetime.patch").read_text()
        self.assertNotIn('GLib.info ("%s", transition_error)', patch)
        self.assertNotIn('GLib.info ("Agent transition failed: %s", transition_error)', patch)

    def test_fork_disconnect_oracle_has_bounded_settling_without_debug_bypasses(self):
        fixture = (REPO / "tests/fixtures/frida-native/core-fork-disconnect.c").read_text()
        self.assertIn(
            "g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND", fixture
        )
        self.assertIn('fail ("runner-stable-tids", NULL);', fixture)
        self.assertIn(
            'require (tid_present ((int) child_pid, first, n1), "business-thread-alive");',
            fixture,
        )
        for debug_bypass in (
            "HYPERHUB_NATIVE_REGRESSION_GDB",
            "PR_SET_PTRACER",
            "waitid (",
            "FAIL target-code=",
        ):
            self.assertNotIn(debug_bypass, fixture)

    def test_retired_controller_cannot_reenter_transition_permission_protocol(self):
        patch = (common.VENDOR / "patches" / "child-agent-lifetime.patch").read_text()
        retire = patch.index("+\t\tprivate void retire_controller () {")
        controller_clear = patch.index("+\t\t\tcontroller = null;", retire)
        fork_clear = patch.index("+\t\t\tfork_permission_pending = false;", controller_clear)
        specialization_clear = patch.index(
            "+\t\t\tspecialization_permission_pending = false;", fork_clear
        )
        discard = patch.index("+\t\t\tdiscard_connections ();", specialization_clear)
        self.assertLess(controller_clear, discard)
        self.assertLess(fork_clear, discard)
        self.assertLess(specialization_clear, discard)

        self.assertIn("+\t\t\t\t\tfork_permission_pending = true;", patch)
        self.assertIn("+\t\t\t\t\tspecialization_permission_pending = true;", patch)
        self.assertIn(
            "+\t\t\tif (actor == CHILD && fork_permission_pending && controller != null) {",
            patch,
        )
        self.assertIn(
            "+\t\t\tif (specialization_permission_pending && controller != null) {",
            patch,
        )
        self.assertIn("Controller returned invalid fork preparation state", patch)
        self.assertIn("Controller returned invalid specialization preparation state", patch)
        self.assertIn(
            "hyperhub_frida_regression_disconnect_before_prepare_v1", patch
        )
        hook = patch.index("+\t\t\t\t\tif (regression_disconnect_before_prepare ())")
        stale_controller = patch.index(
            "+\t\t\t\t\t\tvar stale_controller = controller;", hook
        )
        connection_drop = patch.index(
            "+\t\t\t\t\t\tdiscard_connections ();", stale_controller
        )
        restore_stale_controller = patch.index(
            "+\t\t\t\t\t\tcontroller = stale_controller;", connection_drop
        )
        typed_error = patch.index(
            "+\t\t\t\t\t\tthrow new Error.INVALID_OPERATION",
            restore_stale_controller,
        )
        prepare = patch.index(
            " \t\t\t\t\tfork_child_id = yield controller.prepare_to_fork", typed_error
        )
        self.assertLess(hook, stale_controller)
        self.assertLess(stale_controller, connection_drop)
        self.assertLess(connection_drop, restore_stale_controller)
        self.assertLess(restore_stale_controller, typed_error)
        self.assertLess(typed_error, prepare)

    def test_cached_download_is_always_rehashed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "download.tar.xz"
            path.write_bytes(b"verified original")
            expected = common.sha256(path)
            with mock.patch.object(bootstrap.urllib.request, "urlopen", side_effect=AssertionError("network")):
                self.assertEqual(bootstrap.fetch("https://invalid.example", path, expected), path)
                path.write_bytes(b"changed cache")
                with self.assertRaises(ValueError):
                    bootstrap.fetch("https://invalid.example", path, expected)

    def test_header_allowlist_excludes_sysroot_inside_the_work_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build, sdk = root / "build-x86_64", root / "deps/sdk-linux-x86_64"
            good = [root / "source/lib/frida.h", build / "src/frida-version.h", build / "lib/config.h",
                    build / "subprojects/frida-gum/gum.h", sdk / "include/glib-2.0/glib.h",
                    sdk / "lib/glib-2.0/include/glibconfig.h"]
            bad = [root / "tools/compiler/include/stdio.h", root / "tools/compiler/sysroot/usr/include/stdlib.h",
                   root / "tmp/wrong.h", sdk / "lib/private.h"]
            module = type("Devkit", (), {})()
            devkit_headers.install_header_allowlist(module, root, build, sdk)
            self.assertEqual(module.exclude_libc_headers(good + bad, {}, []), good)

    def test_archive_verifier_rejects_truncation_and_wrong_machine(self):
        def archive(machine):
            object_bytes = b"\x7fELF\x02\x01" + b"\0" * 12 + struct.pack("<H", machine)
            header = b"object.o/".ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + b"100644".ljust(8)
            header += str(len(object_bytes)).encode().ljust(10) + b"`\n"
            return b"!<arch>\n" + header + object_bytes
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "libfrida-core.a"
            path.write_bytes(archive(62))
            self.assertEqual(verify.archive_machines(path), {62})
            path.write_bytes(archive(183))
            self.assertEqual(verify.archive_machines(path), {183})
            path.write_bytes(archive(62)[:-1])
            with self.assertRaises(ValueError):
                verify.archive_machines(path)


class SdkArchiveAuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="frida sdk archive ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sdk = self.root / "deps/sdk-linux-x86_64"
        (self.sdk / "lib").mkdir(parents=True)
        self.official = {f"lib/lib{name}-2.0.a": ("official " + name).encode()
                         for name in ("glib", "gio", "gobject")}
        with tarfile.open(self.root / "deps/sdk-linux-x86_64.tar.xz", "w:xz") as archive:
            for name, contents in self.official.items():
                item = tarfile.TarInfo("./" + name)
                item.size = len(contents)
                archive.addfile(item, io.BytesIO(contents))
                (self.sdk / name).write_bytes(contents)
        self.provenance = self.root / "glib-provenance-x86_64.json"

    def check(self):
        build_glib.verify_sdk_archives(self.root, self.sdk, "x86_64")

    def rebuild(self, component):
        path = self.sdk / f"lib/lib{component}-2.0.a"
        path.with_name(path.stem + ".original.a").write_bytes(path.read_bytes())
        path.write_bytes(("rebuilt patched " + component).encode())
        return {"original_archive_sha256": hashlib.sha256(self.official["lib/" + path.name]).hexdigest(),
                "fixed_archive_sha256": common.sha256(path)}

    def test_legacy_recorded_glib_override_remains_accepted(self):
        self.check()
        glib = self.rebuild("glib")
        with self.assertRaises(ValueError):
            self.check()
        self.provenance.write_text(json.dumps({"fixed_archive_sha256": glib["fixed_archive_sha256"]}))
        self.check()

    def test_unrecorded_gio_modification_is_rejected(self):
        self.provenance.write_text(json.dumps(self.rebuild("glib")))
        self.rebuild("gio")
        with self.assertRaisesRegex(ValueError, "Unverified SDK archive modification"):
            self.check()

    def test_exact_recorded_glib_and_gio_are_accepted_and_audited(self):
        report = {**self.rebuild("glib"), "gio": self.rebuild("gio")}
        self.provenance.write_text(json.dumps(report))
        self.check()
        rows = json.loads((self.root / "sdk-archive-audit-x86_64.json").read_text())
        self.assertEqual([row["file"] for row in rows if row["allowed_glib_override"]], ["lib/libglib-2.0.a"])
        self.assertEqual([row["file"] for row in rows if row["allowed_gio_override"]], ["lib/libgio-2.0.a"])

    def test_other_archive_cannot_be_authorized_by_provenance(self):
        report = {**self.rebuild("glib"), "gio": self.rebuild("gio"), "gobject": self.rebuild("gobject")}
        self.provenance.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, "Unverified SDK archive modification"):
            self.check()

    def test_tampered_fixed_hash_or_archive_is_rejected_for_both_libraries(self):
        report = {**self.rebuild("glib"), "gio": self.rebuild("gio")}
        for component in ("glib", "gio"):
            with self.subTest(component=component, tamper="hash"):
                changed = json.loads(json.dumps(report))
                record = changed if component == "glib" else changed["gio"]
                record["fixed_archive_sha256"] = "0" * 64
                self.provenance.write_text(json.dumps(changed))
                with self.assertRaisesRegex(ValueError, "Unverified SDK archive modification"):
                    self.check()
            with self.subTest(component=component, tamper="archive"):
                self.provenance.write_text(json.dumps(report))
                path = self.sdk / f"lib/lib{component}-2.0.a"
                contents = path.read_bytes()
                path.write_bytes(contents + b"tamper")
                with self.assertRaisesRegex(ValueError, "Unverified SDK archive modification"):
                    self.check()
                path.write_bytes(contents)

    def test_original_backup_and_original_provenance_are_checked_for_both_libraries(self):
        report = {**self.rebuild("glib"), "gio": self.rebuild("gio")}
        for component in ("glib", "gio"):
            with self.subTest(component=component, tamper="backup"):
                self.provenance.write_text(json.dumps(report))
                path = self.sdk / f"lib/lib{component}-2.0.original.a"
                contents = path.read_bytes()
                path.write_bytes(b"unverified original")
                with self.assertRaisesRegex(ValueError, "Preserved original archive"):
                    self.check()
                path.write_bytes(contents)
            with self.subTest(component=component, tamper="original hash"):
                changed = json.loads(json.dumps(report))
                record = changed if component == "glib" else changed["gio"]
                record["original_archive_sha256"] = "0" * 64
                self.provenance.write_text(json.dumps(changed))
                with self.assertRaisesRegex(ValueError, "Recorded original archive"):
                    self.check()

    def test_build_requests_and_installs_both_libraries_with_compatible_provenance(self):
        build = self.root / "glib-build-x86_64"
        build.mkdir()
        (build / "build.ninja").touch()
        (build / "config.h").write_text("#undef HAVE_EVENTFD\n")
        contents = {name: b"!<arch>\n" + name.encode() for name in ("glib", "gio")}

        def make(**kwargs):
            self.assertEqual(kwargs["targets"], ["glib-2.0", "gio-2.0"])
            self.assertEqual(kwargs["builddir"], build)
            for name, data in contents.items():
                (build / name).mkdir()
                (build / name / f"lib{name}-2.0.a").write_bytes(data)

        deps = SimpleNamespace(ensure_toolchain=lambda *args: (self.root / "toolchain", None),
                               ensure_sdk=lambda *args: (self.sdk, None),
                               load_dependency_parameters=lambda: SimpleNamespace(packages={
                                   "glib": SimpleNamespace(version=common.MANIFEST["source"]["glib"]["revision"], options=[])}))
        modules = {"releng": SimpleNamespace(deps=deps),
                   "releng.machine_spec": SimpleNamespace(MachineSpec=SimpleNamespace(parse=lambda value: value)),
                   "releng.meson_configure": SimpleNamespace(configure=mock.Mock()),
                   "releng.meson_make": SimpleNamespace(make=make)}
        with mock.patch.dict(sys.modules, modules), mock.patch.object(build_glib, "cap_ninja"):
            result = build_glib.build_glib(self.root, "x86_64", {"x86_64": self.root / "compiler"}, {}, 1)
        self.assertEqual(result, self.sdk)
        report = json.loads(self.provenance.read_text())
        self.assertEqual(report["architecture"], "x86_64")
        self.assertEqual(report["glib_revision"], common.MANIFEST["source"]["glib"]["revision"])
        self.assertFalse(report["have_eventfd"])
        for component in ("glib", "gio"):
            path = self.sdk / f"lib/lib{component}-2.0.a"
            self.assertEqual(path.read_bytes(), contents[component])
            record = report if component == "glib" else report["gio"]
            self.assertEqual(record["fixed_archive_sha256"], common.sha256(path))
            self.assertEqual(record["original_archive_sha256"], hashlib.sha256(self.official["lib/" + path.name]).hexdigest())
        self.check()

    def test_thin_archives_are_materialized_independently_for_both_libraries(self):
        for component in ("glib", "gio"):
            with self.subTest(component=component):
                library = self.root / ("build space/" + component) / f"lib{component}-2.0.a"
                library.parent.mkdir(parents=True)
                library.write_bytes(b"!<thin>\n")
                target = self.sdk / "lib" / library.name
                complete = b"!<arch>\n" + component.encode()

                def archive(command, **kwargs):
                    self.assertEqual(command, [self.root / "compiler/x86_64-linux-gnu-ar", "-M"])
                    self.assertEqual(kwargs["cwd"], library.parent)
                    merged = library.with_name(library.stem + "-hyperhub-merged.a")
                    self.assertEqual(kwargs["input"], f"create {merged.name}\naddlib {library.name}\nsave\nend\n")
                    merged.write_bytes(complete)

                with mock.patch.object(build_glib, "run", side_effect=archive) as run:
                    record = build_glib.install_sdk_archive(library, target, self.root / "compiler", "x86_64-linux-gnu")
                run.assert_called_once()
                self.assertEqual(target.read_bytes(), complete)
                self.assertEqual(record["fixed_archive_sha256"], common.sha256(target))
                self.assertEqual(target.with_name(target.stem + ".original.a").read_bytes(), self.official["lib/" + target.name])


class HelperArtifactTests(unittest.TestCase):
    def test_nolibc_input_is_the_fixed_official_v62_header_subset(self):
        specification = json.loads(build_helpers.NOLIBC.read_text())
        self.assertEqual(specification["revision"], "c9c3395d5e3dcc6daee66c6908354d47bf98cb0c")
        self.assertEqual(specification["directory"], "tools/include/nolibc")
        self.assertEqual(len(specification["headers"]), 19)
        self.assertTrue({"arch-aarch64.h", "arch-i386.h", "arch-x86_64.h", "nolibc.h"}.issubset(specification["headers"]))
        for digest in [*specification["headers"].values(), specification["tweaks_sha256"],
                       specification["compatibility_patch_sha256"]]:
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
        compatibility = build_helpers.NOLIBC_COMPATIBILITY
        self.assertEqual(common.sha256(compatibility), specification["compatibility_patch_sha256"])
        patch = compatibility.read_text()
        self.assertIn("+#define __KERNEL_STRICT_NAMES", patch)
        self.assertIn("+typedef signed long suseconds_t;", patch)
        self.assertIn(" #include <linux/time.h>", patch)
        self.assertIn("+# elif defined (__NR_socketcall)", patch)
        self.assertIn("+  return my_syscall2 (__NR_socketcall, 8 /* SYS_SOCKETPAIR */, args);", patch)
        for macro in ("FD_CLR", "FD_SET", "FD_ISSET", "FD_ZERO"):
            self.assertIn(f"+#undef {macro}", patch)

    @staticmethod
    def elf(arch="x86_64", entry="frida_load", fault=None):
        wide, machine, _ = build_helpers.MACHINES[arch]
        wide = wide == 2
        names = b"\0.shstrtab\0.strtab\0.symtab\0.payload\0.extra\0"
        strings = b"\0" + entry.encode() + b"\0"
        fmt = "<IBBHQQ" if wide else "<IIIBBH"
        symbol = (1, 0x12, 0, 0 if fault == "undefined" else 4, 1 if fault == "entry" else 0, 4)
        if not wide:
            symbol = (symbol[0], symbol[4], symbol[5], symbol[1], symbol[2], symbol[3])
        symbols = bytes(struct.calcsize(fmt)) + struct.pack(fmt, *symbol)
        parts = [(1, 3, 0, names), (11, 3, 0, strings), (19, 2, 0, symbols), (27, 1, 6, b"code")]
        if fault in ("relocation", "needed", "textrel", "flags_textrel", "bss"):
            kind = {"relocation": 4, "needed": 6, "textrel": 6, "flags_textrel": 6, "bss": 8}[fault]
            tag, value = {"needed": (1, 0), "textrel": (22, 0), "flags_textrel": (30, 4)}.get(
                fault, (0, 0))
            dynamic = struct.pack("<qQ" if wide else "<iI", tag, value)
            parts.append((36, kind, 2, dynamic if kind == 6 else b"bad"))
        data = bytearray(64 if wide else 52)
        sections = [(0,) * 10]
        for name, kind, flags, content in parts:
            sections.append((name, kind, flags, 0, len(data), len(content), 2 if kind == 2 else 0,
                             0, 1, struct.calcsize(fmt) if kind == 2 else 0))
            data.extend(content)
        offset = len(data)
        section_fmt = "<IIQQQQIIQQ" if wide else "<IIIIIIIIII"
        for section in sections:
            data.extend(struct.pack(section_fmt, *section))
        data[:16] = bytes([127, 69, 76, 70, 2 if wide else 1, 1, 1]) + bytes(9)
        header = (3, machine + (1 if fault == "machine" else 0), 1, 0, 0, offset, 0,
                  64 if wide else 52, 56 if wide else 32, 0, 64 if wide else 40, len(sections), 1)
        struct.pack_into("<HHIQQQIHHHHHH" if wide else "<HHIIIIIHHHHHH", data, 16, *header)
        return bytes(data)

    def test_payload_contract_for_all_supported_machines_and_rejected_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            elf, binary = Path(directory) / "loader.so", Path(directory) / "loader.bin"
            binary.write_bytes(b"code")
            for arch in build_helpers.MACHINES:
                elf.write_bytes(self.elf(arch))
                self.assertEqual(build_helpers.verify_payload(elf, binary, arch, "frida_load")["payload_address"], 0)
            for fault in ("undefined", "entry", "machine", "relocation", "needed", "textrel",
                          "flags_textrel", "bss"):
                with self.subTest(fault=fault), self.assertRaises(ValueError):
                    elf.write_bytes(self.elf(fault=fault))
                    build_helpers.verify_payload(elf, binary, "x86_64", "frida_load")
            elf.write_bytes(self.elf())
            binary.write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "differs from its ELF"):
                build_helpers.verify_payload(elf, binary, "x86_64", "frida_load")

    def test_architecture_matrix_and_explicit_cross_tools(self):
        self.assertEqual(build_helpers.ARCHITECTURES, {"x86_64": ("x86_64", "x86"), "aarch64": ("arm64",)})
        with mock.patch.object(build_helpers, "prepare_helpers_source", side_effect=AssertionError("unsupported target")):
            with self.assertRaisesRegex(ValueError, "Unsupported"):
                build_helpers.build_helpers(Path("unused"), "mips", {}, {})
        tools = {name: Path("/private tool's/bin") / name for name in ("c", "ar", "strip", "objcopy")}
        cross = build_helpers.cross_file("x86", tools)
        self.assertIn("objcopy = '''/private tool's/bin/objcopy'''", cross)
        self.assertIn("cpu_family = 'x86'", cross)
        self.assertIn("needs_exe_wrapper = true", cross)

    def test_scratch_source_is_reconstructed_and_warm_mutation_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "source/src/linux/helpers"
            (original / "patches").mkdir(parents=True)
            (root / "tmp").mkdir()
            for name in ("loader.c", "inject-context.h", "helper.lds", "meson.build"):
                (original / name).write_text("reviewed helper\n")
            patch = original / "patches/linux-nolibc-tweaks.patch"
            patch.write_text("--- a/tools/include/nolibc/nolibc.h\n+++ b/tools/include/nolibc/nolibc.h\n@@ -1 +1 @@\n-before\n+after\n")
            compatibility = root / "compatibility.patch"
            compatibility.write_text(
                "--- a/ext/linux/tools/include/nolibc/types.h\n"
                "+++ b/ext/linux/tools/include/nolibc/types.h\n"
                "@@ -1 +1,2 @@\n+#define __KERNEL_STRICT_NAMES\n #include <linux/time.h>\n")
            spec = root / "nolibc.json"
            spec.write_text(json.dumps({"revision": "fixed", "directory": "tools/include/nolibc",
                                       "headers": {
                                           "nolibc.h": hashlib.sha256(b"before\n").hexdigest(),
                                           "types.h": hashlib.sha256(b"#include <linux/time.h>\n").hexdigest(),
                                       },
                                       "tweaks_sha256": common.sha256(patch),
                                       "compatibility_patch_sha256": common.sha256(compatibility)}))
            def fetch(url, path, expected):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"before\n" if path.name == "nolibc.h" else b"#include <linux/time.h>\n")
                self.assertEqual(common.sha256(path), expected)
                return path
            with mock.patch.object(build_helpers, "NOLIBC", spec), \
                 mock.patch.object(build_helpers, "NOLIBC_COMPATIBILITY", compatibility), \
                 mock.patch.object(build_helpers, "fetch", side_effect=fetch), \
                 mock.patch.object(build_helpers, "run", wraps=common.run) as git_run:
                destination, report = build_helpers.prepare_helpers_source(root)
                self.assertEqual((destination / "ext/linux/tools/include/nolibc/nolibc.h").read_text(), "after\n")
                types = (destination / "ext/linux/tools/include/nolibc/types.h").read_text()
                self.assertLess(types.index("__KERNEL_STRICT_NAMES"), types.index("linux/time.h"))
                self.assertIn("loader.c", report["source_files"])
                build_helpers.prepare_helpers_source(root)
                (destination / "loader.c").write_text("tampered")
                with self.assertRaisesRegex(ValueError, "Warm helper source"):
                    build_helpers.prepare_helpers_source(root)
            for call in git_run.call_args_list:
                command = [str(value) for value in call.args[0]]
                self.assertEqual(command[0], "git")
                self.assertIn("core.autocrlf=false", command)
                self.assertIn("core.whitespace=blank-at-eol,blank-at-eof,space-before-tab", command)
                self.assertIn("apply.whitespace=nowarn", command)
                self.assertIn("apply.ignoreWhitespace=false", command)
            self.assertEqual((original / "loader.c").read_text(), "reviewed helper\n")

    def test_helper_compiler_must_report_a_nonempty_pinned_sysroot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compiler = root / "compiler"
            triplet = "test-linux-gnu"
            for suffix in ("gcc", "gcc-ar", "strip", "objcopy", "readelf", "gcc-nm"):
                path = compiler / (triplet + "-" + suffix)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"tool")
            for path in (root / "source/releng/meson/meson.py",
                         root / "deps/toolchain-linux-x86_64/bin/ninja",
                         root / "deps/toolchain-linux-x86_64/bin/ninja.upstream"):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"tool")
            manifest = {"toolchains": {"x86_64": {"triplet": triplet}},
                        "source": {"meson": "fixed"}}
            failures = [subprocess.CalledProcessError(1, ["gcc", "-print-sysroot"]), "\n"]
            for failure in failures:
                with self.subTest(failure=repr(failure)), \
                     mock.patch.object(build_helpers, "MANIFEST", manifest), \
                     mock.patch.object(build_helpers.subprocess, "check_output", side_effect=failure):
                    with self.assertRaisesRegex(ValueError, "does not report a pinned sysroot"):
                        build_helpers.helper_tools(root, "x86_64", {"x86_64": compiler})

    def test_both_x64_helpers_and_x86_compat_are_built_and_warm_outputs_rechecked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tmp").mkdir()
            tools = {name: root / name for name in ("meson", "ninja", "objcopy", "c", "ar", "strip")}
            def run(command, **kwargs):
                if command[0] == sys.executable:
                    build = command[3]
                    (build / "meson-info").mkdir(parents=True)
                    (build / "meson-info/intro-compilers.json").write_text(json.dumps({"host": {"c": {"exelist": [str(tools["c"])]}}}))
                elif command[0] == tools["ninja"]:
                    build = command[4]
                    arch = build.name.removeprefix("helpers-build-")
                    for name, entry in (("bootstrapper", "frida_bootstrap"), ("loader", "frida_load")):
                        (build / (name + ".so")).write_bytes(self.elf(arch, entry))
                        (build / (name + ".bin")).write_bytes(b"code")
                elif command[0] == tools["objcopy"]:
                    command[-1].write_bytes(b"code")
                else:
                    self.fail(f"Unexpected build command: {command}")
            with mock.patch.object(build_helpers, "prepare_helpers_source", return_value=(root / "private-source", {"source_files": {"loader.c": "fixed"}})), \
                 mock.patch.object(build_helpers, "helper_tools", return_value=(tools, {"tools": "fixed"})), \
                 mock.patch.object(build_helpers, "run", side_effect=run) as calls:
                artifacts = build_helpers.build_helpers(root, "x86_64", {}, {})
                self.assertEqual({p.name for p in (artifacts / "native").iterdir()}, {"x86_64", "x86"})
                calls.reset_mock()
                build_helpers.build_helpers(root, "x86_64", {}, {})
                self.assertEqual(calls.call_count, 4)  # independent extraction verification only
                (artifacts / "native/x86/loader.bin").write_bytes(b"tampered")
                with self.assertRaisesRegex(ValueError, "differs from its ELF"):
                    build_helpers.build_helpers(root, "x86_64", {}, {})
                (artifacts / "native/x86/loader.bin").write_bytes(b"code")
                (root / "helpers-build-x86/loader.so").unlink()
                with self.assertRaisesRegex(ValueError, "Incomplete helper build"):
                    build_helpers.build_helpers(root, "x86_64", {}, {})


class GlibcRequirementTests(unittest.TestCase):
    def test_baseline_and_the_pinned_optional_weak_hook_are_accepted(self):
        symbols = """   12: 00000000 0 FUNC GLOBAL DEFAULT UND malloc@GLIBC_2.2.5 (2)
   13: 00000000 0 FUNC GLOBAL DEFAULT UND pthread_create@GLIBC_2.5 (3)
   14: 00000000 0 FUNC WEAK DEFAULT UND __libc_dlopen_mode@GLIBC_PRIVATE (17)
"""
        result = verify.glibc_requirements(symbols, (2, 5))
        self.assertEqual(result["maximum_glibc"], [2, 5])
        self.assertEqual(result["optional_weak_private_symbols"], ["__libc_dlopen_mode"])

    def test_new_numeric_requirements_and_unreviewed_private_symbols_are_rejected(self):
        baseline = "12: 00000000 0 FUNC GLOBAL DEFAULT UND malloc@GLIBC_2.2.5 (2)\n"
        for line in ["13: 00000000 0 FUNC GLOBAL DEFAULT UND sqrtf@GLIBC_2.43 (3)",
                     "13: 00000000 0 FUNC GLOBAL DEFAULT UND __libc_dlopen_mode@GLIBC_PRIVATE (3)",
                     "13: 00000000 0 FUNC WEAK DEFAULT UND unknown_hook@GLIBC_PRIVATE (3)"]:
            with self.assertRaisesRegex(ValueError, line.split()[7]):
                verify.glibc_requirements(baseline + line, (2, 5))


class ConfiguredCompilerTests(unittest.TestCase):
    def test_exact_prefixed_tools_are_required_even_when_host_compilers_exist(self):
        with tempfile.TemporaryDirectory(prefix="baseline compiler ") as directory:
            tools = Path(directory) / "bin"
            triplet = "x86_64-linux-gnu"
            compiler_configuration.require_tool({"c": [str(tools / (triplet + "-gcc")), "-O2"]},
                                                 "c", tools, triplet, "gcc")
            for command in (["/usr/bin/cc"], ["gcc"], [str(tools / (triplet + "-g++"))]):
                with self.assertRaises(ValueError):
                    compiler_configuration.require_tool({"c": command}, "c", tools, triplet, "gcc")


class MultiplePatchTests(unittest.TestCase):
    def test_complete_multi_patch_tree_and_extra_changes_are_checked(self):
        with tempfile.TemporaryDirectory(prefix="frida patches ") as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            files = {"first.c": "int first = 0;\n", "second.c": "int second = 0;\n", "extra.c": "int extra = 0;\n"}
            for name, contents in files.items():
                (source / name).write_text(contents)
            subprocess.run(["git", "add", "--", *files], cwd=source, check=True)
            # A baseline tree object is sufficient; this fixture creates no commit.
            reference = subprocess.check_output(["git", "write-tree"], cwd=source, text=True).strip()
            vendor = root / "vendor"
            (vendor / "patches").mkdir(parents=True)
            manifest = {"patches": {}, "patch_files": {}}
            for name in ("first.c", "second.c"):
                changed = files[name].replace("= 0", "= 1")
                patch = "".join(difflib.unified_diff(files[name].splitlines(True), changed.splitlines(True),
                                                   fromfile="a/" + name, tofile="b/" + name))
                patch_name = name + ".patch"
                (vendor / "patches" / patch_name).write_text(patch)
                manifest["patches"][patch_name] = hashlib.sha256(patch.encode()).hexdigest()
                manifest["patch_files"][patch_name] = {name: hashlib.sha256(changed.encode()).hexdigest()}
            names = tuple(manifest["patches"])
            with mock.patch.object(bootstrap, "MANIFEST", manifest), mock.patch.object(bootstrap, "VENDOR", vendor):
                for name in names:
                    bootstrap.apply_patch(source, name)
                bootstrap.verify_source_changes(source, names, reference)
                # Reuse verifies both applied patches, not just reverse-apply context.
                for name in names:
                    bootstrap.apply_patch(source, name)
                with (source / "first.c").open("a") as stream:
                    stream.write("/* unreviewed change beyond the patch hunk */\n")
                with self.assertRaises(ValueError):
                    bootstrap.verify_source_changes(source, names, reference)
                (source / "first.c").write_text("int first = 1;\n")
                (source / "extra.c").write_text("int extra = 99;\n")
                # Staging an extra edit must not hide it from the reference tree.
                subprocess.run(["git", "add", "extra.c"], cwd=source, check=True)
                with self.assertRaises(ValueError):
                    bootstrap.verify_source_changes(source, names, reference)


if __name__ == "__main__":
    unittest.main()
