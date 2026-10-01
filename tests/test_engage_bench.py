"""Hermetic tests for blkchain.eval.engage_bench.

Covers the lab-host guard (the sole lab-only control), the lab-config
loader/validator, the network-only scope builder, the subprocess client, the
defensive extractor, the grounded detection scorer, and the committed example template. The
lab-host guard does no DNS resolution, so no test touches the network.
"""
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from blkchain.eval import engage_bench
from blkchain.eval.engage_bench import (
    BlkError,
    Detection,
    ExpectedService,
    KnownVuln,
    LabConfig,
    LabConfigError,
    LabTarget,
    ReconObserved,
    RunAggregate,
    TargetScore,
    aggregate_runs,
    build_report,
    build_scope_text,
    canon_host,
    class_match,
    extract_detections,
    extract_recon,
    is_lab_host,
    load_lab_config,
    main,
    parse_target,
    run_engage,
    score_batch,
    score_target,
)


class _TempConfigMixin:
    def _write(self, text):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = Path(d) / "config.json"
        path.write_text(text, encoding="utf-8")
        return path

    def _write_bytes(self, data):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = Path(d) / "config.json"
        path.write_bytes(data)
        return path


class IsLabHostTest(unittest.TestCase):
    def test_is_lab_host_accepts_private_and_reserved(self):
        accepted = [
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "192.0.2.10",
            "198.51.100.5",
            "203.0.113.7",
            "10.0.0.0/24",
            "localhost",
            "box.test",
            "db.internal",
            "printer.local",
            "app.example",
            "x.invalid",
        ]
        for value in accepted:
            with self.subTest(value=value):
                self.assertTrue(is_lab_host(value))

    def test_is_lab_host_rejects_public_ip(self):
        # IP literals, empty, char-invalid, and numeric-looking non-IPs are all
        # refused with no DNS resolution.
        for value in [
            "8.8.8.8", "1.1.1.1", "93.184.216.34", "", "not a host",
            "256.256.256.256",
        ]:
            with self.subTest(value=value):
                self.assertFalse(is_lab_host(value))

    def test_is_lab_host_rejects_non_str(self):
        for value in [123, None, ["10.0.0.5"], 10.0]:
            with self.subTest(value=value):
                self.assertFalse(is_lab_host(value))

    def test_is_lab_host_rejects_char_injection(self):
        # Embedded newline/space/slash must fail on char validation BEFORE the
        # reserved-suffix check.
        for value in ["a.com\nb.test", "evil.com b.test", "evil.com/x.test"]:
            with self.subTest(value=value):
                self.assertFalse(is_lab_host(value))

    def test_is_lab_host_rejects_ipv6_tunneling_literals(self):
        # IPv4-mapped carrying a public v4, and 6to4, must refuse (IP path).
        self.assertFalse(is_lab_host("::ffff:8.8.8.8"))
        self.assertFalse(is_lab_host("2002:0808:0808::"))

    def test_is_lab_host_refuses_nonreserved_hostname(self):
        # No resolver exists: a non-reserved hostname is refused outright,
        # including .lab (a delegated public gTLD), with no DNS and no TOCTOU.
        for value in ["box.corp", "internal-box.corp", "web.lab"]:
            with self.subTest(value=value):
                self.assertFalse(is_lab_host(value))


class LoadLabConfigTest(_TempConfigMixin, unittest.TestCase):
    def test_load_lab_config_missing_file(self):
        missing = Path(tempfile.gettempdir()) / "no-such-engage-config-xyz.json"
        with self.assertRaises(LabConfigError):
            load_lab_config(missing)

    def test_load_lab_config_not_json(self):
        path = self._write("{bad")
        with self.assertRaises(LabConfigError):
            load_lab_config(path)

    def test_load_lab_config_not_utf8(self):
        # A non-UTF-8 file -> LabConfigError, not a raw UnicodeDecodeError.
        path = self._write_bytes(b"\xff\xfe\x00not utf8")
        with self.assertRaises(LabConfigError):
            load_lab_config(path)

    def test_load_lab_config_not_dict(self):
        path = self._write("[]")
        with self.assertRaises(LabConfigError):
            load_lab_config(path)

    def test_load_lab_config_lab_flag_required(self):
        # Missing, string "true", and 1 all fail: must be exactly True.
        for doc in [
            {"targets": [{"host": "10.0.0.5"}]},
            {"lab": "true", "targets": [{"host": "10.0.0.5"}]},
            {"lab": 1, "targets": [{"host": "10.0.0.5"}]},
        ]:
            with self.subTest(doc=doc):
                path = self._write(json.dumps(doc))
                with self.assertRaises(LabConfigError):
                    load_lab_config(path)

    def test_load_lab_config_empty_targets(self):
        path = self._write(json.dumps({"lab": True, "targets": []}))
        with self.assertRaises(LabConfigError):
            load_lab_config(path)

    def test_load_lab_config_non_lab_host_refused(self):
        path = self._write(json.dumps({"lab": True, "targets": [{"host": "8.8.8.8"}]}))
        with self.assertRaises(LabConfigError):
            load_lab_config(path)

    def test_load_lab_config_target_not_dict(self):
        path = self._write(json.dumps({"lab": True, "targets": ["10.0.0.5"]}))
        with self.assertRaises(LabConfigError):
            load_lab_config(path)

    def test_load_lab_config_empty_host(self):
        path = self._write(json.dumps({"lab": True, "targets": [{"host": ""}]}))
        with self.assertRaises(LabConfigError):
            load_lab_config(path)

    def test_load_lab_config_malformed_target(self):
        no_host = self._write(json.dumps({"lab": True, "targets": [{"port": 80}]}))
        with self.assertRaises(LabConfigError):
            load_lab_config(no_host)

        bad_port = self._write(
            json.dumps(
                {
                    "lab": True,
                    "targets": [
                        {
                            "host": "10.0.0.5",
                            "expected_services": [{"port": "nope"}],
                        }
                    ],
                }
            )
        )
        with self.assertRaises(LabConfigError):
            load_lab_config(bad_port)

    def test_load_lab_config_known_vuln_missing_class(self):
        path = self._write(
            json.dumps(
                {
                    "lab": True,
                    "targets": [
                        {"host": "10.0.0.5", "known_vulns": [{"port": 80}]}
                    ],
                }
            )
        )
        with self.assertRaises(LabConfigError):
            load_lab_config(path)

    def test_load_lab_config_host_injection_refused(self):
        path = self._write(
            json.dumps({"lab": True, "targets": [{"host": "evil.com\n10.0.0.5"}]})
        )
        with self.assertRaises(LabConfigError):
            load_lab_config(path)

    def test_load_lab_config_out_of_scope_injection_refused(self):
        path = self._write(
            json.dumps(
                {
                    "lab": True,
                    "targets": [{"host": "10.0.0.5"}],
                    "out_of_scope": ["x\n8.8.8.8"],
                }
            )
        )
        with self.assertRaises(LabConfigError):
            load_lab_config(path)

    def test_load_lab_config_unknown_top_level_key(self):
        path = self._write(
            json.dumps(
                {"lab": True, "targets": [{"host": "10.0.0.5"}], "danger": 1}
            )
        )
        with self.assertRaises(LabConfigError):
            load_lab_config(path)

    def test_load_lab_config_refuses_nonreserved_hostname(self):
        # A non-reserved private hostname cannot be a lab host (no DNS); refused.
        path = self._write(
            json.dumps({"lab": True, "targets": [{"host": "box.corp"}]})
        )
        with self.assertRaises(LabConfigError):
            load_lab_config(path)

    def test_load_lab_config_happy(self):
        path = self._write(
            json.dumps(
                {
                    "lab": True,
                    "targets": [
                        {
                            "host": "10.0.0.5",
                            "expected_assets": ["10.0.0.5", "db.internal"],
                            "expected_services": [
                                {"port": 80, "product": "nginx"},
                                {"host": "db.internal", "port": 5432},
                            ],
                            "known_vulns": [
                                {"port": 80, "class": "idor", "cwe": "CWE-639"},
                                {"class": "version-disclosure"},
                            ],
                        },
                        {"host": "192.0.2.10"},
                    ],
                    "out_of_scope": ["203.0.113.0/24"],
                }
            )
        )
        config = load_lab_config(path)
        self.assertIsInstance(config, LabConfig)
        self.assertEqual(len(config.targets), 2)
        self.assertEqual(
            config.recon_goal,
            "enumerate assets and services; detect known vulnerabilities; "
            "do not exploit",
        )
        first = config.targets[0]
        self.assertEqual(first.host, "10.0.0.5")
        self.assertEqual(first.expected_assets, ("10.0.0.5", "db.internal"))
        self.assertEqual(len(first.expected_services), 2)
        self.assertIsInstance(first.expected_services[0], ExpectedService)
        # service host defaults to the target host when omitted.
        self.assertEqual(first.expected_services[0].host, "10.0.0.5")
        self.assertEqual(first.expected_services[0].port, 80)
        self.assertEqual(first.expected_services[1].host, "db.internal")
        self.assertEqual(len(first.known_vulns), 2)
        self.assertIsInstance(first.known_vulns[0], KnownVuln)
        self.assertEqual(first.known_vulns[0].vuln_class, "idor")
        self.assertEqual(first.known_vulns[0].host, "10.0.0.5")
        self.assertEqual(first.known_vulns[0].port, 80)
        # host-level vuln: port None, host defaults to target.
        self.assertIsNone(first.known_vulns[1].port)
        self.assertEqual(config.out_of_scope, ("203.0.113.0/24",))
        self.assertEqual(config.targets[1].expected_services, ())


class BuildScopeTextTest(unittest.TestCase):
    def test_build_scope_text_network_only(self):
        config = LabConfig(
            recon_goal="g",
            targets=(
                LabTarget(host="10.0.0.5"),
                LabTarget(host="192.0.2.10"),
            ),
            out_of_scope=("203.0.113.9",),
        )
        text = build_scope_text(config)
        self.assertIn("10.0.0.5", text)
        self.assertIn("192.0.2.10", text)
        self.assertIn("!203.0.113.9", text)
        lines = text.splitlines()
        # The local keyword must never appear as a standalone scope line.
        self.assertNotIn("local", lines)

    def test_build_scope_text_refuses_non_lab_host(self):
        # Defense in depth: a LabConfig built directly with a public host is
        # refused at scope-build time.
        config = LabConfig(recon_goal="g", targets=(LabTarget(host="8.8.8.8"),))
        with self.assertRaises(LabConfigError):
            build_scope_text(config)


class ExampleTemplateTest(unittest.TestCase):
    def test_example_template_is_valid_lab_config(self):
        path = Path(engage_bench.__file__).with_name("engage_targets.example.json")
        # The template uses only IP/CIDR literals + reserved-suffix names, so it
        # passes the strict (no-DNS) lab-host guard.
        config = load_lab_config(path)
        self.assertTrue(config.targets)
        raw = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn("_README", raw)
        for target in config.targets:
            with self.subTest(host=target.host):
                self.assertTrue(is_lab_host(target.host))
                self.assertFalse(target.host.endswith(".lab"))


def _ip_config(goal="enumerate services"):
    return LabConfig(recon_goal=goal, targets=(LabTarget(host="10.0.0.5"),))


class _FakeStream:
    def __init__(self, chunks=()):
        self._chunks = list(chunks)

    def read1(self, n):
        return self._chunks.pop(0) if self._chunks else b""

    def close(self):
        pass


class _FakePopen:
    def __init__(self, *, stdout_chunks=(), stderr_chunks=(), returncode=0, timeout=False):
        self.stdout = _FakeStream(stdout_chunks)
        self.stderr = _FakeStream(stderr_chunks)
        self.returncode = returncode
        self._timeout = timeout
        self._waited = False

    def wait(self, timeout=None):
        if self._timeout and not self._waited:
            self._waited = True
            raise engage_bench.subprocess.TimeoutExpired(cmd="blk", timeout=timeout)
        return self.returncode

    def kill(self):
        pass


class _TempDirMixin:
    def _tmpdir(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return Path(d)


class FindBlkTest(_TempDirMixin, unittest.TestCase):
    def test_find_blk_env_and_path(self):
        not_exec = self._tmpdir() / "notexec"
        not_exec.write_text("x", encoding="utf-8")  # regular, no execute bit
        with mock.patch.dict(os.environ, {"BLK_BIN": str(not_exec)}):
            with self.assertRaises(BlkError):
                engage_bench.find_blk()
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch.object(engage_bench.shutil, "which", lambda name: None):
                with self.assertRaises(BlkError):
                    engage_bench.find_blk()


class RunEngageTest(_TempDirMixin, unittest.TestCase):
    def _run(self, *, workspace, exec_fn):
        with mock.patch.object(engage_bench, "find_blk", lambda: "/usr/bin/blk"):
            return run_engage(
                _ip_config(),
                LabTarget(host="10.0.0.5"),
                workspace=str(workspace),
                exec_fn=exec_fn,
            )

    def test_run_engage_nonzero_exit(self):
        ws = self._tmpdir()
        with self.assertRaises(BlkError) as ctx:
            self._run(workspace=ws, exec_fn=lambda argv, timeout: (1, b"", b"boom"))
        self.assertIn("status", str(ctx.exception))

    def test_run_engage_oversize(self):
        ws = self._tmpdir()
        fake = _FakePopen(stdout_chunks=[b"x" * (engage_bench._OUTPUT_CAP + 10)])
        with mock.patch.object(engage_bench, "find_blk", lambda: "/usr/bin/blk"), \
                mock.patch.object(engage_bench.subprocess, "Popen", lambda *a, **k: fake):
            with self.assertRaises(BlkError):
                run_engage(_ip_config(), LabTarget(host="10.0.0.5"), workspace=str(ws))

    def test_run_engage_timeout(self):
        ws = self._tmpdir()
        fake = _FakePopen(timeout=True)
        with mock.patch.object(engage_bench, "find_blk", lambda: "/usr/bin/blk"), \
                mock.patch.object(engage_bench.subprocess, "Popen", lambda *a, **k: fake):
            with self.assertRaises(BlkError):
                run_engage(
                    _ip_config(), LabTarget(host="10.0.0.5"), workspace=str(ws), timeout=0.01
                )

    def test_run_engage_missing_report(self):
        ws = self._tmpdir()  # no report.json written
        with self.assertRaises(BlkError):
            self._run(workspace=ws, exec_fn=lambda argv, timeout: (0, b"", b""))

    def test_run_engage_invalid_report(self):
        ws = self._tmpdir()
        (ws / "report.json").write_text("{bad", encoding="utf-8")
        with self.assertRaises(BlkError):
            self._run(workspace=ws, exec_fn=lambda argv, timeout: (0, b"", b""))

    def test_run_engage_happy(self):
        ws = self._tmpdir()
        report = {"engagement": {"Tasks": []}}
        (ws / "report.json").write_text(json.dumps(report), encoding="utf-8")
        got = self._run(workspace=ws, exec_fn=lambda argv, timeout: (0, b"", b""))
        self.assertEqual(got, report)

    def test_run_engage_argv_shape(self):
        ws = self._tmpdir()
        (ws / "report.json").write_text(json.dumps({}), encoding="utf-8")
        seen = {}

        def _capture(argv, timeout):
            seen["argv"] = argv
            return (0, b"", b"")

        self._run(workspace=ws, exec_fn=_capture)
        argv = seen["argv"]
        self.assertEqual(argv[0], "/usr/bin/blk")
        self.assertEqual(argv[1:4], ["engage", "--auto", "--scope"])
        self.assertIn("--workspace", argv)
        self.assertNotIn("local", argv)
        self.assertNotIn("arm", argv)
        # goal words appended verbatim after the workspace.
        self.assertEqual(argv[-2:], ["enumerate", "services"])

    def test_run_engage_oversize_report(self):
        ws = self._tmpdir()
        (ws / "report.json").write_text(
            json.dumps({"engagement": {"Tasks": []}}), encoding="utf-8"
        )
        with mock.patch.object(engage_bench, "_OUTPUT_CAP", 4):
            with self.assertRaises(BlkError) as ctx:
                self._run(workspace=ws, exec_fn=lambda argv, timeout: (0, b"", b""))
        self.assertIn("exceeded", str(ctx.exception))

    def test_run_engage_removes_auto_workspace(self):
        report = {"engagement": {"Tasks": []}}
        created = {}

        real_mkdtemp = tempfile.mkdtemp

        def _mkdtemp(*a, **k):
            d = real_mkdtemp(*a, **k)
            created["ws"] = d
            (Path(d) / "report.json").write_text(json.dumps(report), encoding="utf-8")
            return d

        with mock.patch.object(engage_bench, "find_blk", lambda: "/usr/bin/blk"), \
                mock.patch.object(engage_bench.tempfile, "mkdtemp", _mkdtemp):
            run_engage(
                _ip_config(), LabTarget(host="10.0.0.5"),
                exec_fn=lambda argv, timeout: (0, b"", b""),
            )
        self.assertFalse(Path(created["ws"]).exists())

    def test_run_engage_removes_auto_workspace_on_error(self):
        created = {}
        real_mkdtemp = tempfile.mkdtemp

        def _mkdtemp(*a, **k):
            d = real_mkdtemp(*a, **k)
            created["ws"] = d
            return d  # no report.json -> run_engage raises

        with mock.patch.object(engage_bench, "find_blk", lambda: "/usr/bin/blk"), \
                mock.patch.object(engage_bench.tempfile, "mkdtemp", _mkdtemp):
            with self.assertRaises(BlkError):
                run_engage(
                    _ip_config(), LabTarget(host="10.0.0.5"),
                    exec_fn=lambda argv, timeout: (0, b"", b""),
                )
        self.assertFalse(Path(created["ws"]).exists())

    def test_run_engage_preserves_operator_workspace(self):
        ws = self._tmpdir()
        report = {"engagement": {"Tasks": []}}
        (ws / "report.json").write_text(json.dumps(report), encoding="utf-8")
        self._run(workspace=ws, exec_fn=lambda argv, timeout: (0, b"", b""))
        self.assertTrue(ws.exists())


class ParseTargetTest(unittest.TestCase):
    def test_parse_target_edge_cases(self):
        self.assertEqual(parse_target("h:22"), ("h", 22))
        self.assertEqual(parse_target("h"), ("h", None))
        self.assertEqual(parse_target(""), ("", None))
        self.assertEqual(parse_target("h:notaport"), ("h", None))
        self.assertEqual(parse_target("10.0.0.1:443"), ("10.0.0.1", 443))

    def test_parse_target_ipv6(self):
        # Unbracketed IPv6 host:port splits off its port; a bare IPv6 does not.
        self.assertEqual(parse_target("fd00::1:443"), ("fd00::1", 443))
        self.assertEqual(parse_target("[fd00::1]:443"), ("fd00::1", 443))
        self.assertEqual(parse_target("fd00::1"), ("fd00::1", None))
        self.assertEqual(parse_target("::1:80"), ("::1", 80))

    def test_parse_target_port_range(self):
        # Ports must be within 0-65535; out-of-range is treated as no port.
        self.assertEqual(parse_target("host:99999"), ("host", None))
        self.assertEqual(parse_target("host:65535"), ("host", 65535))
        self.assertEqual(parse_target("host:0"), ("host", 0))
        self.assertEqual(parse_target("[fd00::1]:70000"), ("[fd00::1]:70000", None))
        self.assertEqual(parse_target("fd00::1:99999"), ("fd00::1:99999", None))


class ExtractTest(unittest.TestCase):
    def test_extract_detections_selects_exploit_only(self):
        report = {
            "engagement": {
                "Tasks": [
                    {"ID": "r1", "Phase": "recon", "Target": "10.0.0.5:80",
                     "Objective": "scan"},
                    {"ID": "e2", "Phase": "exploit", "Kind": "exploit",
                     "Target": "10.0.0.5:80", "Objective": "IDOR on endpoint",
                     "Surface": "web", "Armed": False,
                     "Citation": {"cwe_class": "CWE-639"}},
                ]
            }
        }
        dets = extract_detections(report)
        self.assertEqual(len(dets), 1)
        d = dets[0]
        self.assertEqual(d.task_id, "e2")
        self.assertEqual(d.host, "10.0.0.5")
        self.assertEqual(d.port, 80)
        self.assertEqual(d.cwe, "CWE-639")
        self.assertEqual(d.vuln_class, "idor on endpoint")
        self.assertFalse(d.armed)

    def test_extract_handles_absent_and_null_fields(self):
        for report in [
            {},
            {"engagement": None},
            {"engagement": {"Tasks": None}},
            None,
        ]:
            with self.subTest(report=report):
                self.assertEqual(extract_detections(report), [])
                obs = extract_recon(report)
                self.assertEqual(obs.assets, set())
                self.assertEqual(obs.services, set())
        null_fields = {
            "engagement": {
                "Tasks": [
                    {"ID": "t", "Phase": "exploit", "Target": None, "Citation": None}
                ]
            }
        }
        dets = extract_detections(null_fields)
        self.assertEqual(len(dets), 1)
        self.assertEqual(dets[0].host, "")
        self.assertIsNone(dets[0].port)
        self.assertEqual(dets[0].cwe, "")

    def test_extract_recon_from_targets_and_evidence(self):
        report = {
            "engagement": {"Tasks": [{"ID": "t1", "Target": "10.0.0.5:443"}]},
            "evidence": {"t1": ["22/tcp open ssh", 123, "noise"]},
        }
        obs = extract_recon(report)
        self.assertIn("10.0.0.5", obs.assets)
        self.assertIn(("10.0.0.5", 443), obs.services)
        self.assertIn(("10.0.0.5", 22), obs.services)


def _report(tasks, *, evidence=None, status="complete"):
    report = {"status": status, "engagement": {"Tasks": tasks}}
    if evidence is not None:
        report["evidence"] = evidence
    return report


class CanonTest(unittest.TestCase):
    def test_canon_host(self):
        self.assertEqual(canon_host("HTTP://Host.TEST."), "host.test")
        self.assertEqual(canon_host("  10.0.0.5  "), "10.0.0.5")
        self.assertEqual(canon_host("https://Printer.Local"), "printer.local")
        self.assertEqual(canon_host(""), "")
        self.assertEqual(canon_host(None), "")


class ClassMatchTest(unittest.TestCase):
    def _det(self, *, objective="", cwe=""):
        return Detection(task_id="t", host="10.0.0.5", port=80,
                         vuln_class=objective.lower(), objective=objective,
                         cwe=cwe, surface="", armed=False)

    def test_class_match_cwe_then_cve_then_keyword(self):
        # CWE equality branch (both have CWE).
        self.assertTrue(class_match(
            KnownVuln(host="10.0.0.5", port=80, vuln_class="x", cwe="CWE-89"),
            self._det(objective="whatever", cwe="CWE-89")))
        self.assertFalse(class_match(
            KnownVuln(host="10.0.0.5", port=80, vuln_class="x", cwe="CWE-89"),
            self._det(objective="whatever", cwe="CWE-79")))
        # CVE-id substring branch (no CWE pair).
        self.assertTrue(class_match(
            KnownVuln(host="10.0.0.5", port=80, vuln_class="CVE-2021-1234"),
            self._det(objective="exploited cve-2021-1234 in service")))
        self.assertFalse(class_match(
            KnownVuln(host="10.0.0.5", port=80, vuln_class="CVE-2021-1234"),
            self._det(objective="some other finding")))
        # keyword-map branch.
        self.assertTrue(class_match(
            KnownVuln(host="10.0.0.5", port=80, vuln_class="idor"),
            self._det(objective="Insecure Direct Object reference on /api")))
        # token fallback branch.
        self.assertTrue(class_match(
            KnownVuln(host="10.0.0.5", port=80, vuln_class="toctou"),
            self._det(objective="a toctou race was found")))

    def test_class_match_fallback_is_word_boundary(self):
        # "rce" must NOT match inside "resource" (unbounded substring bug).
        self.assertFalse(class_match(
            KnownVuln(host="10.0.0.5", port=80, vuln_class="rce"),
            self._det(objective="access to resource /admin")))
        # A genuine word-boundary hit still matches.
        self.assertTrue(class_match(
            KnownVuln(host="10.0.0.5", port=80, vuln_class="rce"),
            self._det(objective="achieve rce on host")))

    def test_class_match_keyword_is_word_boundary(self):
        # "version" keyword must not fire on "conversion" (substring).
        self.assertFalse(class_match(
            KnownVuln(host="10.0.0.5", port=80, vuln_class="version-disclosure"),
            self._det(objective="currency conversion endpoint")))
        self.assertTrue(class_match(
            KnownVuln(host="10.0.0.5", port=80, vuln_class="version-disclosure"),
            self._det(objective="server version disclosure in banner")))

    def test_class_match_cve_is_exact_not_prefix(self):
        # CVE-2021-1234 must NOT match a detection citing CVE-2021-12340.
        self.assertFalse(class_match(
            KnownVuln(host="10.0.0.5", port=80, vuln_class="CVE-2021-1234"),
            self._det(objective="exploited CVE-2021-12340 in service")))
        self.assertTrue(class_match(
            KnownVuln(host="10.0.0.5", port=80, vuln_class="CVE-2021-1234"),
            self._det(objective="exploited CVE-2021-1234 in service")))


class ScoreTargetTest(unittest.TestCase):
    def test_coverage_denominator_is_ground_truth(self):
        target = LabTarget(
            host="10.0.0.5",
            expected_assets=("10.0.0.5", "db.internal", "cache.internal"),
        )
        # Observed finds only one of the three expected assets (plus an extra).
        report = _report([
            {"ID": "r1", "Target": "10.0.0.5:80"},
            {"ID": "r2", "Target": "extra.internal:80"},
        ])
        score = score_target(target, report)
        self.assertEqual(score.assets_expected, 3)
        self.assertEqual(score.assets_found, 1)
        self.assertAlmostEqual(score.asset_coverage, 1 / 3)

    def test_service_coverage_requires_host_and_port(self):
        target = LabTarget(
            host="10.0.0.5",
            expected_services=(
                ExpectedService(host="10.0.0.5", port=80),
                ExpectedService(host="db.internal", port=5432),
            ),
        )
        # 10.0.0.5:80 matches; db.internal:5432 does not (only 10.0.0.5:5432 seen).
        report = _report([
            {"ID": "r1", "Target": "10.0.0.5:80"},
            {"ID": "r2", "Target": "10.0.0.5:5432"},
        ])
        score = score_target(target, report)
        self.assertEqual(score.services_expected, 2)
        self.assertEqual(score.services_found, 1)
        self.assertAlmostEqual(score.service_coverage, 0.5)

    def test_detection_requires_class_match(self):
        # Right host + port, wrong class -> NOT detected.
        target = LabTarget(
            host="10.0.0.5",
            known_vulns=(KnownVuln(host="10.0.0.5", port=80, vuln_class="idor"),),
        )
        report = _report([
            {"ID": "e1", "Phase": "exploit", "Target": "10.0.0.5:80",
             "Objective": "reflected XSS"},
        ])
        score = score_target(target, report)
        self.assertEqual(score.true_positives, 0)
        self.assertAlmostEqual(score.detection_rate, 0.0)

    def test_detection_credits_known_vuln_subhost(self):
        # Grounded detection matches by the KNOWN vuln's host, not the target.
        target = LabTarget(
            host="10.0.0.5",
            known_vulns=(KnownVuln(host="db.internal", port=5432, vuln_class="sqli"),),
        )
        report = _report([
            {"ID": "e1", "Phase": "exploit", "Target": "db.internal:5432",
             "Objective": "SQL injection (SQLi) in query"},
        ])
        score = score_target(target, report)
        self.assertEqual(score.true_positives, 1)

    def test_fp_closed_world_counts_unlisted(self):
        target = LabTarget(
            host="10.0.0.5",
            known_vulns=(KnownVuln(host="10.0.0.5", port=80, vuln_class="idor"),),
            vuln_ground_truth_complete=True,
        )
        report = _report([
            {"ID": "e1", "Phase": "exploit", "Target": "10.0.0.5:80",
             "Objective": "IDOR on /api"},
            {"ID": "e2", "Phase": "exploit", "Target": "10.0.0.5:80",
             "Objective": "reflected XSS"},
        ])
        score = score_target(target, report)
        self.assertTrue(score.closed_world)
        self.assertEqual(score.true_positives, 1)
        self.assertEqual(score.false_positives, 1)

    def test_fp_open_world_only_contradictions(self):
        target = LabTarget(
            host="10.0.0.5",
            expected_assets=("10.0.0.5",),
            expected_services=(ExpectedService(host="10.0.0.5", port=80),),
            enumeration_complete=True,
        )
        report = _report([
            {"ID": "e1", "Phase": "exploit", "Target": "10.0.0.5:80",
             "Objective": "some finding"},
            {"ID": "e2", "Phase": "exploit", "Target": "10.0.0.6:8080",
             "Objective": "hallucinated host finding"},
        ])
        score = score_target(target, report)
        self.assertFalse(score.closed_world)
        self.assertEqual(score.contradictions, 1)
        self.assertEqual(score.false_positives, 1)

    def test_fp_open_world_no_enum_flag_is_zero(self):
        target = LabTarget(
            host="10.0.0.5",
            expected_assets=("10.0.0.5",),
            expected_services=(ExpectedService(host="10.0.0.5", port=80),),
        )
        report = _report([
            {"ID": "e2", "Phase": "exploit", "Target": "10.0.0.6:8080",
             "Objective": "hallucinated host finding"},
        ])
        score = score_target(target, report)
        self.assertEqual(score.false_positives, 0)
        self.assertEqual(score.contradictions, 0)

    def test_dedupe_services_across_quotes(self):
        target = LabTarget(host="10.0.0.5")
        report = _report(
            [
                {"ID": "t1", "Target": "10.0.0.5:80"},
                {"ID": "t2", "Target": "10.0.0.5:443"},
            ],
            evidence={
                "t1": ["80/tcp open http\n443/tcp open https\n80/tcp open http"],
            },
        )
        observed = extract_recon(report)
        self.assertEqual(
            observed.services, {("10.0.0.5", 80), ("10.0.0.5", 443)}
        )

    def test_service_match_needs_cooccurrence(self):
        target = LabTarget(
            host="10.0.0.5",
            expected_services=(ExpectedService(host="10.0.0.5", port=80),),
        )
        # Host present on a different port, and the port present on a different
        # host; neither is a (host,port) co-occurrence.
        report = _report([
            {"ID": "r1", "Target": "10.0.0.5:443"},
            {"ID": "r2", "Target": "other.internal:80"},
        ])
        score = score_target(target, report)
        self.assertEqual(score.services_found, 0)

    def test_weighted_detection_rate(self):
        target = LabTarget(
            host="10.0.0.5",
            known_vulns=(
                KnownVuln(host="10.0.0.5", port=80, vuln_class="idor",
                          severity="critical"),
                KnownVuln(host="10.0.0.5", port=443, vuln_class="sqli",
                          severity="low"),
            ),
        )
        report = _report([
            {"ID": "e1", "Phase": "exploit", "Target": "10.0.0.5:80",
             "Objective": "IDOR on /api"},
        ])
        score = score_target(target, report)
        self.assertAlmostEqual(score.detection_rate, 0.5)
        self.assertAlmostEqual(score.weighted_detection_rate, 4.0 / 5.0)

    def test_run_status_flags_incomplete(self):
        target = LabTarget(host="10.0.0.5")
        report = _report([], status="aborted")
        score = score_target(target, report)
        self.assertEqual(score.run_status, "aborted")
        text = build_report([score])
        self.assertIn("aborted", text)

    def test_substring_class_is_not_a_true_positive(self):
        # KnownVuln class "rce" must not be credited by "resource" substring.
        target = LabTarget(
            host="10.0.0.5",
            known_vulns=(KnownVuln(host="10.0.0.5", port=80, vuln_class="rce"),),
        )
        report = _report([
            {"ID": "e1", "Phase": "exploit", "Target": "10.0.0.5:80",
             "Objective": "access to resource /admin"},
        ])
        score = score_target(target, report)
        self.assertEqual(score.true_positives, 0)
        self.assertAlmostEqual(score.detection_rate, 0.0)

    def test_ipv6_hostport_service_grounds(self):
        target = LabTarget(
            host="fd00::1",
            expected_services=(ExpectedService(host="fd00::1", port=443),),
        )
        report = _report([{"ID": "r1", "Target": "fd00::1:443"}])
        score = score_target(target, report)
        self.assertEqual(score.services_found, 1)
        self.assertAlmostEqual(score.service_coverage, 1.0)

    def test_reworded_same_class_dedupes_once(self):
        # Two reworded XSS detections on the same host:port are one finding.
        target = LabTarget(
            host="10.0.0.5",
            known_vulns=(KnownVuln(host="10.0.0.5", port=80, vuln_class="idor"),),
            vuln_ground_truth_complete=True,
        )
        report = _report([
            {"ID": "e1", "Phase": "exploit", "Target": "10.0.0.5:80",
             "Objective": "reflected XSS in search"},
            {"ID": "e2", "Phase": "exploit", "Target": "10.0.0.5:80",
             "Objective": "cross-site scripting on the search box"},
        ])
        score = score_target(target, report)
        self.assertEqual(score.detections_total, 1)
        self.assertEqual(score.false_positives, 1)
        self.assertEqual(score.true_positives, 0)

    def _fp_target(self):
        return LabTarget(
            host="10.0.0.5",
            known_vulns=(KnownVuln(host="10.0.0.5", port=80, vuln_class="idor"),),
            vuln_ground_truth_complete=True,
        )

    def test_multiclass_not_overcollapsed(self):
        # A detection matching {version-disclosure, anonymous-access} is distinct
        # from a pure {version-disclosure} on the same host:port; they must not
        # collapse (first-match-wins would under-count FP).
        report = _report([
            {"ID": "e1", "Phase": "exploit", "Target": "10.0.0.5:80",
             "Objective": "anonymous access exposing version info"},
            {"ID": "e2", "Phase": "exploit", "Target": "10.0.0.5:80",
             "Objective": "server version disclosure in banner"},
        ])
        score = score_target(self._fp_target(), report)
        self.assertEqual(score.detections_total, 2)
        self.assertEqual(score.false_positives, 2)

    def test_distinct_classes_not_collapsed(self):
        report = _report([
            {"ID": "e1", "Phase": "exploit", "Target": "10.0.0.5:80",
             "Objective": "SQL injection in login"},
            {"ID": "e2", "Phase": "exploit", "Target": "10.0.0.5:80",
             "Objective": "reflected XSS in search"},
        ])
        score = score_target(self._fp_target(), report)
        self.assertEqual(score.detections_total, 2)
        self.assertEqual(score.false_positives, 2)

    def test_distinct_unmapped_classes_not_collapsed(self):
        report = _report([
            {"ID": "e1", "Phase": "exploit", "Target": "10.0.0.5:80",
             "Objective": "weird finding alpha"},
            {"ID": "e2", "Phase": "exploit", "Target": "10.0.0.5:80",
             "Objective": "weird finding beta"},
        ])
        score = score_target(self._fp_target(), report)
        self.assertEqual(score.detections_total, 2)
        self.assertEqual(score.false_positives, 2)

    def test_nmap_out_of_range_port_not_added(self):
        target = LabTarget(host="10.0.0.5")
        report = _report(
            [{"ID": "t1", "Target": "10.0.0.5:80"}],
            evidence={"t1": ["70000/tcp open http", "22/tcp open ssh"]},
        )
        observed = extract_recon(report)
        self.assertIn(("10.0.0.5", 22), observed.services)
        self.assertNotIn(("10.0.0.5", 70000), observed.services)


class ScoreBatchTest(unittest.TestCase):
    def test_batch_isolates_failure_first_target(self):
        config = LabConfig(
            recon_goal="enumerate",
            targets=(LabTarget(host="10.0.0.5"), LabTarget(host="10.0.0.6")),
        )
        good = _report([])

        def run_fn(cfg, t):
            if t.host == "10.0.0.5":
                raise BlkError("boom on first")
            return good

        scores = score_batch(config, run_fn=run_fn)
        self.assertEqual(len(scores), 2)
        self.assertIsNotNone(scores[0].error)
        self.assertIn("boom", scores[0].error)
        self.assertIsNone(scores[1].error)

    def test_batch_runs_multiplies(self):
        config = LabConfig(recon_goal="enumerate", targets=(LabTarget(host="10.0.0.5"),))
        scores = score_batch(config, runs=3, run_fn=lambda cfg, t: _report([]))
        self.assertEqual(len(scores), 3)


class AggregateRunsTest(unittest.TestCase):
    def test_aggregate_runs_mean_and_stdev(self):
        config = LabConfig(
            recon_goal="enumerate",
            targets=(LabTarget(host="10.0.0.5", expected_assets=("10.0.0.5",)),),
        )
        reports = iter([
            _report([]),                              # asset_coverage 0.0
            _report([{"ID": "r", "Target": "10.0.0.5:80"}]),  # asset_coverage 1.0
        ])
        scores = score_batch(config, runs=2, run_fn=lambda cfg, t: next(reports))
        agg = aggregate_runs(scores)
        self.assertIsInstance(agg, RunAggregate)
        self.assertEqual(agg.n, 2)
        self.assertAlmostEqual(agg.asset_coverage_mean, 0.5)
        self.assertAlmostEqual(agg.asset_coverage_stdev, 0.7071067811865476, places=6)
        self.assertFalse(agg.single_run_noisy)

    def test_aggregate_runs_single_is_noisy(self):
        config = LabConfig(recon_goal="g", targets=(LabTarget(host="10.0.0.5"),))
        scores = score_batch(config, runs=1, run_fn=lambda cfg, t: _report([]))
        agg = aggregate_runs(scores)
        self.assertEqual(agg.n, 1)
        self.assertTrue(agg.single_run_noisy)
        self.assertEqual(agg.asset_coverage_stdev, 0.0)

    def test_aggregate_runs_weighted_rate_excludes_errored_run(self):
        # Run 0 errors; later runs detect a critical vuln. The aggregated
        # weighted rate must reflect the successful runs, not run 0's 0.0.
        config = LabConfig(
            recon_goal="enumerate",
            targets=(
                LabTarget(
                    host="10.0.0.5",
                    known_vulns=(
                        KnownVuln(host="10.0.0.5", port=80, vuln_class="idor",
                                  severity="critical"),
                    ),
                ),
            ),
        )
        detect_report = _report([
            {"ID": "e1", "Phase": "exploit", "Target": "10.0.0.5:80",
             "Objective": "IDOR on /api"},
        ])
        calls = {"n": 0}

        def run_fn(cfg, t):
            calls["n"] += 1
            if calls["n"] == 1:
                raise BlkError("first run failed")
            return detect_report

        scores = score_batch(config, runs=3, run_fn=run_fn)
        agg = aggregate_runs(scores)
        self.assertEqual(agg.n, 2)
        self.assertAlmostEqual(agg.weighted_detection_rate_mean, 1.0)
        summary = engage_bench._target_summary("10.0.0.5", scores)
        self.assertAlmostEqual(summary["weighted_detection_rate_mean"], 1.0)


class NoLeakTest(unittest.TestCase):
    def test_scope_and_goal_do_not_leak_ground_truth(self):
        config = LabConfig(
            recon_goal="enumerate assets and services; do not exploit",
            targets=(
                LabTarget(
                    host="10.0.0.5",
                    expected_assets=("leak-asset-token",),
                    expected_services=(
                        ExpectedService(host="10.0.0.5", port=80,
                                        product="SuperSecretProduct9000"),
                    ),
                    known_vulns=(
                        KnownVuln(host="10.0.0.5", port=80,
                                  vuln_class="zzzsecretclass"),
                    ),
                ),
            ),
        )
        scope_text = build_scope_text(config)
        goal = config.recon_goal
        for token in ("leak-asset-token", "SuperSecretProduct9000", "zzzsecretclass"):
            self.assertNotIn(token, scope_text)
            self.assertNotIn(token, goal)


class MainTest(_TempDirMixin, unittest.TestCase):
    def _config_file(self):
        path = self._tmpdir() / "cfg.json"
        path.write_text(
            json.dumps({"lab": True, "targets": [{"host": "10.0.0.5"}]}),
            encoding="utf-8",
        )
        return str(path)

    def test_main_refuses_without_config(self):
        called = {"ran": False}

        def _never(cfg, t):
            called["ran"] = True
            raise AssertionError("must not run")

        with mock.patch.object(engage_bench, "run_engage", _never):
            with contextlib.redirect_stderr(io.StringIO()):
                rc = main(["--report", "x"])
        self.assertEqual(rc, 2)
        self.assertFalse(called["ran"])

    def test_main_rejects_bad_config(self):
        bad = self._tmpdir() / "bad.json"
        bad.write_text(json.dumps({"lab": True, "targets": [{"host": "8.8.8.8"}]}),
                       encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()):
            rc = main(["--config", str(bad)])
        self.assertEqual(rc, 2)

    def test_main_happy_with_stubbed_run(self):
        cfg = self._config_file()
        report = _report([])
        out = io.StringIO()
        with mock.patch.object(engage_bench, "run_engage",
                               lambda c, t, **k: report):
            with contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(io.StringIO()):
                rc = main(["--config", cfg, "--json"])
        self.assertEqual(rc, 0)
        parsed = json.loads(out.getvalue())
        self.assertIn("aggregate", parsed)

    def test_main_runs_flag(self):
        cfg = self._config_file()
        report = _report([])
        out = io.StringIO()
        with mock.patch.object(engage_bench, "run_engage",
                               lambda c, t, **k: report):
            with contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(io.StringIO()):
                rc = main(["--config", cfg, "--json", "--runs", "3"])
        self.assertEqual(rc, 0)
        parsed = json.loads(out.getvalue())
        self.assertEqual(parsed["targets"][0]["runs"], 3)

    def test_main_reports_error_exit_one(self):
        cfg = self._config_file()

        def _boom_run(c, t, **k):
            raise BlkError("exec failed")

        with mock.patch.object(engage_bench, "run_engage", _boom_run):
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                rc = main(["--config", cfg, "--json"])
        self.assertEqual(rc, 1)

    def test_main_rejects_nonpositive_timeout(self):
        cfg = self._config_file()
        called = {"ran": False}

        def _never(c, t, **k):
            called["ran"] = True
            raise AssertionError("must not run")

        for bad in ["0", "-5"]:
            with self.subTest(timeout=bad):
                with mock.patch.object(engage_bench, "run_engage", _never):
                    with contextlib.redirect_stderr(io.StringIO()):
                        rc = main(["--config", cfg, "--timeout", bad])
                self.assertEqual(rc, 2)
        self.assertFalse(called["ran"])


class ConfigFlagsTest(_TempDirMixin, unittest.TestCase):
    def test_load_parses_completeness_flags(self):
        path = self._tmpdir() / "cfg.json"
        path.write_text(
            json.dumps({
                "lab": True,
                "targets": [{
                    "host": "10.0.0.5",
                    "vuln_ground_truth_complete": True,
                    "enumeration_complete": True,
                }],
            }),
            encoding="utf-8",
        )
        config = load_lab_config(str(path))
        self.assertTrue(config.targets[0].vuln_ground_truth_complete)
        self.assertTrue(config.targets[0].enumeration_complete)

    def test_load_rejects_non_bool_flag(self):
        path = self._tmpdir() / "cfg.json"
        path.write_text(
            json.dumps({
                "lab": True,
                "targets": [{"host": "10.0.0.5", "vuln_ground_truth_complete": "yes"}],
            }),
            encoding="utf-8",
        )
        with self.assertRaises(LabConfigError):
            load_lab_config(str(path))

    def test_load_rejects_unknown_target_key(self):
        path = self._tmpdir() / "cfg.json"
        path.write_text(
            json.dumps({"lab": True, "targets": [{"host": "10.0.0.5", "danger": 1}]}),
            encoding="utf-8",
        )
        with self.assertRaises(LabConfigError):
            load_lab_config(str(path))


class BuildReportTest(unittest.TestCase):
    def test_build_report_renders(self):
        scores = [
            TargetScore(
                host="10.0.0.5",
                assets_expected=2, assets_found=1,
                services_expected=2, services_found=2,
                vulns_expected=1, true_positives=1,
                false_positives=1, contradictions=0, detections_total=2,
                asset_coverage=0.5, service_coverage=1.0,
                detection_rate=1.0, weighted_detection_rate=1.0,
                run_status="complete", closed_world=False,
            )
        ]
        text = build_report(scores)
        self.assertIn("10.0.0.5", text)
        self.assertIn("Asset coverage", text)
        self.assertIn("Service coverage", text)
        self.assertIn("Detection rate", text)
        self.assertIn("False positives", text)


if __name__ == "__main__":
    unittest.main()
