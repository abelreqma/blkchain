''
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

DEFAULT_RECON_GOAL = (
    "enumerate assets and services; detect known vulnerabilities; "
    "do not exploit"
)

# Provably-non-public-resolving reserved suffixes only. RFC6761 (test/example/
# invalid/localhost), RFC6762 (local, mDNS link-local), ICANN private-use
# (internal). `.lab` is a DELEGATED public gTLD and is deliberately excluded.
_RESERVED_SUFFIXES = {"test", "example", "invalid", "localhost", "local", "internal"}

# A hostname may contain only DNS label characters. Anything else (whitespace,
# newline, slash, control chars) is an injection attempt and is refused BEFORE
# the reserved-suffix/resolve logic, so the value that is validated is exactly
# the value `build_scope_text` later emits (no validate-normalized/emit-raw gap).
_HOSTNAME_RE = re.compile(r"[A-Za-z0-9.-]+")
# An out_of_scope entry is one bare token: a host/IP/CIDR, so the allowed set
# additionally includes `:` and `/`. It is NOT lab-host-validated for lab-ness,
# but it must not inject extra scope lines.
_SCOPE_TOKEN_RE = re.compile(r"[A-Za-z0-9.:/-]+")

_ALLOWED_TOP_LEVEL_KEYS = {"lab", "targets", "recon_goal", "out_of_scope", "_README"}
_ALLOWED_TARGET_KEYS = {
    "host",
    "expected_assets",
    "expected_services",
    "known_vulns",
    "vuln_ground_truth_complete",
    "enumeration_complete",
}


class LabConfigError(Exception):
    """A lab config is missing, malformed, or names a non-lab host."""


class BlkError(Exception):
    """A `blk` subprocess call failed (reserved for the later client layer)."""


@dataclass(frozen=True)
class ExpectedService:
    host: str
    port: int
    product: str = ""  # optional, informational


@dataclass(frozen=True)
class KnownVuln:
    host: str
    port: Optional[int]  # None = host-level (e.g. a web class)
    vuln_class: str  # e.g. "idor", "cve", "version-disclosure"
    cwe: str = ""  # optional, e.g. "CWE-89"
    severity: str = ""  # optional


@dataclass(frozen=True)
class LabTarget:
    host: str
    expected_assets: tuple[str, ...] = ()
    expected_services: tuple[ExpectedService, ...] = ()
    known_vulns: tuple[KnownVuln, ...] = ()
    # vuln_ground_truth_complete: the known_vulns list is exhaustive, so a
    # right-host detection of an unlisted class counts as a false positive
    # (closed-world scoring). enumeration_complete: expected_assets/services are
    # the complete enumeration, so a detection on an unlisted host/port is a
    # contradiction false positive. Both default False (cannot-judge).
    vuln_ground_truth_complete: bool = False
    enumeration_complete: bool = False


@dataclass(frozen=True)
class LabConfig:
    recon_goal: str
    targets: tuple[LabTarget, ...]
    out_of_scope: tuple[str, ...] = ()


def _ip_is_lab(text: str) -> bool:
    """True iff an IP or CIDR literal is non-public.

    A single IP is parsed with ip_address first so IPv6 embedding/tunneling
    forms cannot smuggle a public address past is_global: an IPv4-mapped v6
    address is judged by its embedded v4, and 6to4/Teredo literals are refused
    outright. Only a genuine CIDR range falls back to ip_network.is_global.
    """
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        try:
            return not ipaddress.ip_network(text, strict=False).is_global
        except ValueError:
            return False
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.sixtofour is not None or addr.teredo is not None:
            return False  # tunneling literal: refuse outright
        if addr.ipv4_mapped is not None:
            return not addr.ipv4_mapped.is_global
    return not addr.is_global


def _looks_like_ip_or_cidr(value: str) -> bool:
    """True iff value parses as an IP or CIDR literal (so a hostname never
    reaches _ip_is_lab)."""
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def is_lab_host(value) -> bool:
    """True iff value is a non-flipping lab identifier.

    Accepts only: an IP/CIDR literal that is non-global (IPv4-mapped IPv6 judged
    by its embedded v4, 6to4/Teredo refused), or a hostname that passes the
    `[A-Za-z0-9.-]` char-set check whose final label is a reserved suffix
    (test/example/invalid/localhost/local/internal) or is bare `localhost`.
    EVERY other hostname is refused, including a privately-resolvable
    non-reserved name and any `.lab` name. No DNS resolution happens, so there is
    no validation-time vs run-time DNS window.
    """
    if not isinstance(value, str):
        return False
    v = value.strip().rstrip(".")
    if not v:
        return False
    if _looks_like_ip_or_cidr(v):
        return _ip_is_lab(v)
    # Hostname path: reject any value with a character outside the DNS label set
    # (whitespace, newline, slash, control chars) before the reserved-suffix check.
    if not _HOSTNAME_RE.fullmatch(v):
        return False
    host = v.lower()
    label = host.rsplit(".", 1)[-1] if "." in host else host
    return host == "localhost" or label in _RESERVED_SUFFIXES


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise LabConfigError(message)


def _parse_expected_service(
    raw, target_host: str, index: int
) -> ExpectedService:
    _require(
        isinstance(raw, dict),
        f"expected_services[{index}] must be an object",
    )
    host = raw.get("host", target_host)
    _require(
        isinstance(host, str) and host.strip() != "",
        f"expected_services[{index}] host must be a non-empty string",
    )
    port = raw.get("port")
    _require(
        isinstance(port, int) and not isinstance(port, bool),
        f"expected_services[{index}] port must be an integer",
    )
    product = raw.get("product", "")
    _require(
        isinstance(product, str),
        f"expected_services[{index}] product must be a string",
    )
    return ExpectedService(host=host, port=port, product=product)


def _parse_known_vuln(raw, target_host: str, index: int) -> KnownVuln:
    _require(isinstance(raw, dict), f"known_vulns[{index}] must be an object")
    host = raw.get("host", target_host)
    _require(
        isinstance(host, str) and host.strip() != "",
        f"known_vulns[{index}] host must be a non-empty string",
    )
    port = raw.get("port")
    _require(
        port is None or (isinstance(port, int) and not isinstance(port, bool)),
        f"known_vulns[{index}] port must be an integer or null",
    )
    vuln_class = raw.get("class")
    _require(
        isinstance(vuln_class, str) and vuln_class.strip() != "",
        f"known_vulns[{index}] requires a non-empty string \"class\"",
    )
    cwe = raw.get("cwe", "")
    _require(isinstance(cwe, str), f"known_vulns[{index}] cwe must be a string")
    severity = raw.get("severity", "")
    _require(
        isinstance(severity, str),
        f"known_vulns[{index}] severity must be a string",
    )
    return KnownVuln(
        host=host,
        port=port,
        vuln_class=vuln_class,
        cwe=cwe,
        severity=severity,
    )


def _parse_target(raw, index: int) -> LabTarget:
    _require(isinstance(raw, dict), f"targets[{index}] must be an object")
    unknown = set(raw) - _ALLOWED_TARGET_KEYS
    _require(
        not unknown,
        f"targets[{index}] has unknown keys: {sorted(unknown)}",
    )
    host = raw.get("host")
    _require(
        isinstance(host, str) and host.strip() != "",
        f"targets[{index}] requires a non-empty string \"host\"",
    )
    _require(
        is_lab_host(host),
        f"target host is not a lab host: {host!r}",
    )
    # Store the stripped host so the validated value equals the value
    # build_scope_text emits (no validate-stripped/emit-raw gap).
    host = host.strip()

    expected_assets_raw = raw.get("expected_assets", [])
    _require(
        isinstance(expected_assets_raw, list),
        f"targets[{index}] expected_assets must be a list",
    )
    assets = []
    for i, asset in enumerate(expected_assets_raw):
        _require(
            isinstance(asset, str) and asset.strip() != "",
            f"targets[{index}] expected_assets[{i}] must be a non-empty string",
        )
        assets.append(asset)

    services_raw = raw.get("expected_services", [])
    _require(
        isinstance(services_raw, list),
        f"targets[{index}] expected_services must be a list",
    )
    services = tuple(
        _parse_expected_service(s, host, i) for i, s in enumerate(services_raw)
    )

    vulns_raw = raw.get("known_vulns", [])
    _require(
        isinstance(vulns_raw, list),
        f"targets[{index}] known_vulns must be a list",
    )
    vulns = tuple(
        _parse_known_vuln(v, host, i) for i, v in enumerate(vulns_raw)
    )

    gt_complete = raw.get("vuln_ground_truth_complete", False)
    _require(
        isinstance(gt_complete, bool),
        f"targets[{index}] vuln_ground_truth_complete must be a boolean",
    )
    enum_complete = raw.get("enumeration_complete", False)
    _require(
        isinstance(enum_complete, bool),
        f"targets[{index}] enumeration_complete must be a boolean",
    )

    return LabTarget(
        host=host,
        expected_assets=tuple(assets),
        expected_services=services,
        known_vulns=vulns,
        vuln_ground_truth_complete=gt_complete,
        enumeration_complete=enum_complete,
    )


def load_lab_config(path) -> LabConfig:
    """Load, validate, and refuse an operator-supplied lab config.

    Refuses (raises LabConfigError) on a missing or unreadable file, invalid
    JSON, a non-dict document, an unknown top-level key, `lab` not exactly True,
    empty/missing targets, a malformed target, or a target host that fails
    `is_lab_host` (IP/CIDR or reserved-suffix names only; no DNS resolution).
    `out_of_scope` entries are NOT lab-host-validated (an exclusion only removes
    scope) but each must be a single bare host/IP/CIDR token (no
    whitespace/control chars) so it cannot inject an extra scope line.
    """
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise LabConfigError(f"lab config not found: {path}") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise LabConfigError(f"lab config could not be read: {path}: {exc}") from exc

    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise LabConfigError(f"lab config is not valid JSON: {exc}") from exc

    _require(isinstance(doc, dict), "lab config must be a JSON object")
    unknown = set(doc) - _ALLOWED_TOP_LEVEL_KEYS
    _require(
        not unknown,
        f"lab config has unknown keys: {sorted(unknown)}",
    )
    _require(doc.get("lab") is True, 'lab config must set "lab": true')

    targets_raw = doc.get("targets")
    _require(
        isinstance(targets_raw, list) and len(targets_raw) > 0,
        "lab config has no targets",
    )
    targets = tuple(
        _parse_target(t, i) for i, t in enumerate(targets_raw)
    )

    recon_goal = doc.get("recon_goal", DEFAULT_RECON_GOAL)
    _require(
        isinstance(recon_goal, str) and recon_goal.strip() != "",
        "recon_goal must be a non-empty string",
    )

    out_of_scope_raw = doc.get("out_of_scope", [])
    _require(
        isinstance(out_of_scope_raw, list),
        "out_of_scope must be a list",
    )
    out_of_scope = []
    for i, entry in enumerate(out_of_scope_raw):
        _require(
            isinstance(entry, str) and entry != "" and bool(_SCOPE_TOKEN_RE.fullmatch(entry)),
            f"out_of_scope[{i}] must be a single bare host/IP/CIDR token",
        )
        out_of_scope.append(entry)

    return LabConfig(
        recon_goal=recon_goal,
        targets=targets,
        out_of_scope=tuple(out_of_scope),
    )


def build_scope_text(config: LabConfig) -> str:
    """Build the NETWORK-only scope file text for `blk engage`.

    In-scope lines are bare hosts; out-of-scope lines are prefixed with `!`.
    The `local` keyword is never emitted. Defense in depth: re-assert every
    in-scope host is a lab host before writing it.
    """
    lines = [t.host for t in config.targets]
    lines += [f"!{h}" for h in config.out_of_scope]
    for t in config.targets:
        if not is_lab_host(t.host):
            raise LabConfigError(f"refusing to scope non-lab host: {t.host!r}")
    return "\n".join(lines) + "\n"


# --- Layer 2: data model for recon/detection results ------------------------


@dataclass(frozen=True)
class Detection:
    task_id: str
    host: str
    port: Optional[int]
    vuln_class: str  # lowercased objective text, used for word-boundary class matching
    objective: str
    cwe: str
    surface: str
    armed: bool


@dataclass
class ReconObserved:
    assets: set  # set[str] of hosts
    services: set  # set[tuple[str, int]] of (host, port)


@dataclass
class TargetScore:
    host: str
    assets_expected: int
    assets_found: int
    services_expected: int
    services_found: int
    vulns_expected: int
    true_positives: int
    false_positives: int
    contradictions: int
    detections_total: int
    asset_coverage: float
    service_coverage: float
    detection_rate: float
    weighted_detection_rate: float
    run_status: str
    closed_world: bool
    error: Optional[str] = None


@dataclass
class RunAggregate:
    n: int
    asset_coverage_mean: float
    asset_coverage_stdev: float
    service_coverage_mean: float
    service_coverage_stdev: float
    detection_rate_mean: float
    detection_rate_stdev: float
    weighted_detection_rate_mean: float
    weighted_detection_rate_stdev: float
    false_positives_mean: float
    false_positives_stdev: float
    single_run_noisy: bool


# --- Layer 2: blk engage subprocess client ----------------------------------

# Bounds on the blk engage subprocess, mirroring blkchain.eval.run (not imported
# so this module stays stdlib-light).
_OUTPUT_CAP = 16 * 1024 * 1024  # max stdout bytes read from blk engage
_STDERR_KEEP = 2048             # stderr bytes kept for the error message
_ENGAGE_TIMEOUT = float(os.environ.get("BLKCHAIN_ENGAGE_BENCH_TIMEOUT", "1200"))
_BUILD_HINT = "build it with: cd cli && go build -o blk ."


def find_blk() -> str:
    """Path of the blk binary: env BLK_BIN, else `blk` on PATH, else BlkError."""
    override = os.environ.get("BLK_BIN", "").strip()
    if override:
        path = Path(override).expanduser()
        if not (path.is_file() and os.access(path, os.X_OK)):
            raise BlkError(f"BLK_BIN is not an executable file: {override} ({_BUILD_HINT})")
        return str(path)
    found = shutil.which("blk")
    if found:
        return found
    raise BlkError(f"blk binary not found: set BLK_BIN or put blk on PATH ({_BUILD_HINT})")


def _drain(stream, keep: int, sink: bytearray, on_over=None) -> None:
    """Read `stream` to EOF, keeping at most `keep` bytes in `sink`. Calls
    `on_over` once when more than `keep` bytes arrive."""
    fired = False
    while True:
        chunk = stream.read1(65536)
        if not chunk:
            return
        room = keep - len(sink)
        if room > 0:
            sink += chunk[:room]
        if len(chunk) > max(room, 0) and not fired:
            fired = True
            if on_over is not None:
                on_over()


def _exec_engage(argv, timeout: float):
    """Run the blk engage argv without a shell, returning (returncode, stdout,
    stderr) bytes. stdin is /dev/null; stdout/stderr are drained with bounds.

    Raises BlkError on a failure to start, a timeout, or stdout larger than
    _OUTPUT_CAP. This is the mock seam: tests patch it, or patch subprocess.Popen
    to exercise the bounds here. Arguments go through argv only.
    """
    try:
        proc = subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise BlkError(f"could not start blk engage: {type(exc).__name__}") from exc

    out, err = bytearray(), bytearray()
    over = threading.Event()

    def _oversize() -> None:
        over.set()
        proc.kill()

    readers = [
        threading.Thread(
            target=_drain, args=(proc.stdout, _OUTPUT_CAP + 1, out, _oversize), daemon=True
        ),
        threading.Thread(
            target=_drain, args=(proc.stderr, _STDERR_KEEP, err), daemon=True
        ),
    ]
    for t in readers:
        t.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise BlkError(f"blk engage timed out after {timeout:g}s") from None
    finally:
        for t in readers:
            t.join(timeout=5)
        if not any(t.is_alive() for t in readers):
            proc.stdout.close()
            proc.stderr.close()

    if over.is_set() or len(out) > _OUTPUT_CAP:
        raise BlkError(f"blk engage output exceeded {_OUTPUT_CAP} bytes")
    return proc.returncode, bytes(out), bytes(err)


def run_engage(
    config: LabConfig,
    target: LabTarget,
    *,
    timeout: float = _ENGAGE_TIMEOUT,
    workspace: Optional[str] = None,
    exec_fn: Callable = _exec_engage,
) -> dict:
    """Run `blk engage --auto` headless against one lab target and return the
    parsed report.json dict.

    RECON + DETECTION ONLY: the argv is
    `[blk, engage, --auto, --scope <file>, --workspace <dir>, *goal.split()]`.
    It never emits the `local` scope keyword and never passes `arm`. The scope
    file is network-only (build_scope_text over a single-target config, keeping
    out_of_scope exclusions). Raises BlkError on a non-zero exit, a timeout, an
    oversize stdout, or a missing/invalid/oversize report.json.

    A temp workspace is created only when `workspace` is None, and it is removed
    on return or raise; an operator-supplied workspace is left untouched.
    """
    binary = find_blk()
    ws = workspace or tempfile.mkdtemp(prefix="engage-bench-")
    owns_ws = workspace is None
    try:
        single = LabConfig(
            recon_goal=config.recon_goal,
            targets=(target,),
            out_of_scope=config.out_of_scope,
        )
        scope_path = Path(ws) / "scope.txt"
        scope_path.write_text(build_scope_text(single), encoding="utf-8")

        goal = config.recon_goal
        argv = [
            binary, "engage", "--auto",
            "--scope", str(scope_path),
            "--workspace", str(ws),
            *goal.split(),
        ]

        rc, _out, err = exec_fn(argv, timeout)
        if rc != 0:
            text = err.decode("utf-8", "replace")
            detail = "".join(
                ch if ch.isprintable() else " " for ch in text
            ).strip()[:200]
            raise BlkError(
                f"blk engage exited with status {rc}: {detail}"
                if detail
                else f"blk engage exited with status {rc}"
            )

        report_path = Path(ws) / "report.json"
        # Bound the report read like any other resource: reject before parsing a
        # report.json larger than the stdout cap.
        try:
            if report_path.stat().st_size > _OUTPUT_CAP:
                raise BlkError(f"blk engage report.json exceeded {_OUTPUT_CAP} bytes")
            raw = report_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise BlkError(
                f"blk engage produced no readable report.json: {exc}"
            ) from exc
        try:
            report = json.loads(raw)
        except (ValueError, RecursionError) as exc:
            raise BlkError(
                f"blk engage report.json is not valid JSON: {exc}"
            ) from exc
        if not isinstance(report, dict):
            raise BlkError("blk engage report.json is not a JSON object")
        return report
    finally:
        if owns_ws:
            shutil.rmtree(ws, ignore_errors=True)


# --- Layer 3: defensive report extraction -----------------------------------

# nmap-style open-port line, e.g. "22/tcp open ssh". Applied per evidence quote
# (MULTILINE) so a multi-line quote still matches each open port.
_NMAP_OPEN_RE = re.compile(r"^(\d{1,5})/(?:tcp|udp)\s+open", re.MULTILINE)

# Leading URL scheme, e.g. "https://", stripped during host canonicalization.
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def canon_host(h) -> str:
    """Canonicalize a host for matching: strip surrounding whitespace, drop a
    leading scheme://, drop a trailing dot, lowercase."""
    h = (h or "").strip()
    h = _SCHEME_RE.sub("", h)
    h = h.rstrip(".")
    return h.strip().lower()


def _tasks(report) -> list:
    eng = report.get("engagement") if isinstance(report, dict) else None
    tasks = eng.get("Tasks") if isinstance(eng, dict) else None
    return [t for t in tasks if isinstance(t, dict)] if isinstance(tasks, list) else []


def _is_ipv6(text: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(text), ipaddress.IPv6Address)
    except ValueError:
        return False


def _valid_port(port: int) -> bool:
    return 0 <= port <= 65535


def parse_target(s):
    """Split a task Target into (host, port|None).

    Handles IPv4 host:port, bracketed IPv6 `[host]:port`, and unbracketed IPv6
    `host:port` (where the port is the trailing numeric group and the prefix is a
    valid IPv6 address). A bare IPv6 with a non-IPv6 prefix before its last group
    (e.g. fd00::1) stays whole with port None. A non-numeric or out-of-range
    (not 0-65535) port yields no port.

    Unbracketed IPv6 host:port is inherently ambiguous (RFC 3986 brackets
    disambiguate); the rsplit heuristic (numeric in-range suffix + valid-IPv6
    prefix) recovers the common cases. A genuine full IPv6 address whose last
    group is a small number with a valid-IPv6 prefix is the documented residual.
    """
    s = s or ""
    if not s:
        return s, None
    if s.startswith("["):
        end = s.find("]")
        if end != -1:
            host = s[1:end]
            rest = s[end + 1:]
            if rest == "":
                return host, None
            if rest.startswith(":") and rest[1:].isdigit():
                port = int(rest[1:])
                if _valid_port(port):
                    return host, port
        return s, None
    n = s.count(":")
    if n == 0:
        return s, None
    if n == 1:
        host, _, port = s.partition(":")
        try:
            value = int(port)
        except ValueError:
            return host, None
        return (host, value) if _valid_port(value) else (host, None)
    # Multiple colons: an unbracketed IPv6, optionally with a trailing :port.
    prefix, _, suffix = s.rpartition(":")
    if suffix.isdigit() and _is_ipv6(prefix):
        port = int(suffix)
        if _valid_port(port):
            return prefix, port
    return s, None


def extract_detections(report) -> list:
    """Detections are tasks with Phase or Kind == 'exploit' (created Armed:false).
    Every field is read defensively; any hop may be absent or null."""
    out = []
    for t in _tasks(report):
        phase = str(t.get("Phase") or "").lower()
        kind = str(t.get("Kind") or "").lower()
        if phase != "exploit" and kind != "exploit":
            continue
        host, port = parse_target(str(t.get("Target") or ""))
        cite = t.get("Citation") if isinstance(t.get("Citation"), dict) else {}
        out.append(
            Detection(
                task_id=str(t.get("ID") or ""),
                host=host,
                port=port,
                vuln_class=str(t.get("Objective") or "").lower(),
                objective=str(t.get("Objective") or ""),
                cwe=str(cite.get("cwe_class") or ""),
                surface=str(t.get("Surface") or ""),
                armed=bool(t.get("Armed")),
            )
        )
    return out


def extract_recon(report) -> ReconObserved:
    """Recover observed assets/services from task Targets plus a heuristic scan
    of evidence quotes for nmap open-port lines.

    report.json does not persist structured asset/service arrays, so this
    recovery is heuristic over the stable report.json contract: hosts and
    host:port pairs come from task Targets, and each evidence quote belonging to
    a task contributes (that task's host, open-port) matches. Non-str quotes are
    skipped.
    """
    assets = set()
    services = set()
    task_host = {}
    for t in _tasks(report):
        host, port = parse_target(str(t.get("Target") or ""))
        host = canon_host(host)
        if host:
            assets.add(host)
        if port is not None:
            services.add((host, port))
        task_host[str(t.get("ID") or "")] = host

    evidence = report.get("evidence") if isinstance(report, dict) else None
    if isinstance(evidence, dict):
        for task_id, quotes in evidence.items():
            host = task_host.get(str(task_id), "")
            if not host or not isinstance(quotes, list):
                continue
            for quote in quotes:
                if not isinstance(quote, str):
                    continue
                for m in _NMAP_OPEN_RE.finditer(quote):
                    try:
                        port = int(m.group(1))
                    except ValueError:
                        continue
                    if not _valid_port(port):
                        continue
                    assets.add(host)
                    services.add((host, port))
    return ReconObserved(assets=assets, services=services)


# Scoring

# Class-keyword map for grounded detection; the class-token word-boundary fallback
# below always applies after these. Extend as needed.
_CLASS_KEYWORDS = {
    "idor": ("idor", "insecure direct object"),
    "sqli": ("sql injection", "sqli"),
    "xss": ("cross-site scripting", "xss"),
    "ssrf": ("ssrf", "server-side request forgery"),
    "version-disclosure": ("version", "disclosure"),
    "anonymous-access": ("anonymous", "unauth"),
}
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Severity weights for the weighted detection rate; unknown/empty -> 1.0.
_SEV_WEIGHT = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0, "info": 0.5}


def _sev_weight(vuln: KnownVuln) -> float:
    return _SEV_WEIGHT.get(vuln.severity.strip().lower(), 1.0)


def _word_match(token: str, hay: str) -> bool:
    """Word-boundary match for `token` in `hay` (both already lowercased).
    re.escape keeps hyphens/spaces in multi-word classes literal."""
    return bool(token) and re.search(rf"\b{re.escape(token)}\b", hay) is not None


def class_match(known: KnownVuln, det: Detection) -> bool:
    """True iff a detection's class matches a known vuln's. Precedence: CWE
    equality (when both carry a CWE) -> exact CVE-id membership -> class-keyword
    map (word-boundary) -> class-token word-boundary fallback. A wrong class is
    not a match, and a token embedded in a longer word does not match."""
    k_cwe, d_cwe = known.cwe.strip().lower(), det.cwe.strip().lower()
    if k_cwe and d_cwe:
        return k_cwe == d_cwe
    hay = (det.objective + " " + det.cwe).lower()
    kcls = known.vuln_class.strip().lower()
    cve = _CVE_RE.search(known.vuln_class) or _CVE_RE.search(known.cwe)
    if cve:
        found = {m.upper() for m in _CVE_RE.findall(hay)}
        return cve.group(0).upper() in found
    for kw in _CLASS_KEYWORDS.get(kcls, ()):
        if _word_match(kw, hay):
            return True
    return _word_match(kcls, hay)


def _canon_class_key(text: str):
    """Canonical dedupe key for a detection's class text: the frozenset of ALL
    _CLASS_KEYWORDS classes whose name or any keyword word-boundary-matches the
    text, so a multi-class finding is not collapsed with a single-class one. If
    no mapped class matches, the whitespace-collapsed lowercased text (unmapped
    findings stay distinct). The result is hashable for use in a dedupe key."""
    low = text.lower()
    matched = frozenset(
        cls
        for cls, keywords in _CLASS_KEYWORDS.items()
        if _word_match(cls, low) or any(_word_match(kw, low) for kw in keywords)
    )
    return matched if matched else " ".join(low.split())


def _grounds(known: KnownVuln, det: Detection) -> bool:
    """A detection grounds a known vuln iff same canon host, matching port (when
    the known vuln sets one), and class_match."""
    if canon_host(known.host) != canon_host(det.host):
        return False
    if known.port is not None and known.port != det.port:
        return False
    return class_match(known, det)


def _dedupe_detections(detections) -> list:
    """Dedupe to one detection per (canon_host, port, canon_class) - membership,
    not occurrence. Reworded detections of the same semantic class on the same
    host:port collapse to one."""
    seen = {}
    for d in detections:
        key = (canon_host(d.host), d.port, _canon_class_key(d.vuln_class))
        if key not in seen:
            seen[key] = d
    return list(seen.values())


def score_target(target: LabTarget, report: dict) -> TargetScore:
    """Score one target using grounded detection and ground-truth
    coverage denominators (asset/service separate), closed-world or
    contradiction-only false positives, and severity-weighted detection rate."""
    observed = extract_recon(report)
    detections = _dedupe_detections(extract_detections(report))

    # Coverage: denominator is the ground-truth count; asset/service reported
    # separately. A service needs host+port co-occurrence.
    assets_expected = len(target.expected_assets)
    services_expected = len(target.expected_services)
    assets_found = sum(
        1 for a in target.expected_assets if canon_host(a) in observed.assets
    )
    services_found = sum(
        1
        for s in target.expected_services
        if (canon_host(s.host), s.port) in observed.services
    )
    asset_coverage = assets_found / assets_expected if assets_expected else 0.0
    service_coverage = (
        services_found / services_expected if services_expected else 0.0
    )

    # Grounded detection: a known vuln is detected iff some detection grounds it.
    detected = [
        v for v in target.known_vulns if any(_grounds(v, d) for d in detections)
    ]
    true_positives = len(detected)
    vulns_expected = len(target.known_vulns)
    detection_rate = true_positives / vulns_expected if vulns_expected else 0.0
    weight_den = sum(_sev_weight(v) for v in target.known_vulns)
    weight_num = sum(_sev_weight(v) for v in detected)
    weighted_detection_rate = weight_num / weight_den if weight_den else 0.0

    # False positives: closed-world (unlisted right-host detection) vs
    # contradiction-only (hallucinated host/port) when enumeration is complete.
    closed_world = target.vuln_ground_truth_complete
    expected_asset_hosts = {canon_host(a) for a in target.expected_assets}
    expected_services = {
        (canon_host(s.host), s.port) for s in target.expected_services
    }

    def _is_contradiction(d: Detection) -> bool:
        ch = canon_host(d.host)
        return ch not in expected_asset_hosts and (ch, d.port) not in expected_services

    contradictions = (
        sum(1 for d in detections if _is_contradiction(d))
        if target.enumeration_complete
        else 0
    )
    if closed_world:
        false_positives = sum(
            1
            for d in detections
            if not any(_grounds(v, d) for v in target.known_vulns)
        )
    elif target.enumeration_complete:
        false_positives = contradictions
    else:
        false_positives = 0

    run_status = str(report.get("status") or "") if isinstance(report, dict) else ""

    return TargetScore(
        host=target.host,
        assets_expected=assets_expected,
        assets_found=assets_found,
        services_expected=services_expected,
        services_found=services_found,
        vulns_expected=vulns_expected,
        true_positives=true_positives,
        false_positives=false_positives,
        contradictions=contradictions,
        detections_total=len(detections),
        asset_coverage=asset_coverage,
        service_coverage=service_coverage,
        detection_rate=detection_rate,
        weighted_detection_rate=weighted_detection_rate,
        run_status=run_status,
        closed_world=closed_world,
    )


def _error_score(target: LabTarget, error: str) -> TargetScore:
    return TargetScore(
        host=target.host,
        assets_expected=len(target.expected_assets),
        assets_found=0,
        services_expected=len(target.expected_services),
        services_found=0,
        vulns_expected=len(target.known_vulns),
        true_positives=0,
        false_positives=0,
        contradictions=0,
        detections_total=0,
        asset_coverage=0.0,
        service_coverage=0.0,
        detection_rate=0.0,
        weighted_detection_rate=0.0,
        run_status="error",
        closed_world=target.vuln_ground_truth_complete,
        error=error,
    )


def score_batch(
    config: LabConfig, *, runs: int = 1, run_fn: Callable = run_engage
) -> list:
    """Run and score every target `runs` times. One run's failure is recorded
    against that target (TargetScore.error) and never aborts the batch. Returns a
    flat list grouped by target (runs scores per target, in target order)."""
    runs = max(1, runs)
    scores = []
    for target in config.targets:
        for _ in range(runs):
            try:
                report = run_fn(config, target)
                scores.append(score_target(target, report))
            except Exception as exc:  # BlkError or any unexpected failure
                scores.append(_error_score(target, str(exc)))
    return scores


def aggregate_runs(scores) -> RunAggregate:
    """Mean and sample stdev of the headline metrics across the given run scores
    (errored runs excluded). n<=1 is labeled a single noisy run with 0.0 stdevs."""
    ok = [s for s in scores if s.error is None]
    n = len(ok)

    def _mean(vals):
        return statistics.fmean(vals) if vals else 0.0

    def _stdev(vals):
        return statistics.stdev(vals) if len(vals) >= 2 else 0.0

    asset = [s.asset_coverage for s in ok]
    service = [s.service_coverage for s in ok]
    detect = [s.detection_rate for s in ok]
    weighted = [s.weighted_detection_rate for s in ok]
    fp = [float(s.false_positives) for s in ok]
    return RunAggregate(
        n=n,
        asset_coverage_mean=_mean(asset),
        asset_coverage_stdev=_stdev(asset),
        service_coverage_mean=_mean(service),
        service_coverage_stdev=_stdev(service),
        detection_rate_mean=_mean(detect),
        detection_rate_stdev=_stdev(detect),
        weighted_detection_rate_mean=_mean(weighted),
        weighted_detection_rate_stdev=_stdev(weighted),
        false_positives_mean=_mean(fp),
        false_positives_stdev=_stdev(fp),
        single_run_noisy=n <= 1,
    )


# --- Layer 4: reporting + CLI -----------------------------------------------


def _aggregate(scores) -> dict:
    assets_expected = sum(s.assets_expected for s in scores)
    assets_found = sum(s.assets_found for s in scores)
    services_expected = sum(s.services_expected for s in scores)
    services_found = sum(s.services_found for s in scores)
    vulns_expected = sum(s.vulns_expected for s in scores)
    true_positives = sum(s.true_positives for s in scores)
    false_positives = sum(s.false_positives for s in scores)
    contradictions = sum(s.contradictions for s in scores)
    detections_total = sum(s.detections_total for s in scores)
    return {
        "targets": len(scores),
        "errors": sum(1 for s in scores if s.error),
        "incomplete_runs": sum(
            1 for s in scores if s.error is None and s.run_status != "complete"
        ),
        "assets_expected": assets_expected,
        "assets_found": assets_found,
        "services_expected": services_expected,
        "services_found": services_found,
        "vulns_expected": vulns_expected,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "contradictions": contradictions,
        "detections_total": detections_total,
        "asset_coverage": (assets_found / assets_expected) if assets_expected else 0.0,
        "service_coverage": (
            (services_found / services_expected) if services_expected else 0.0
        ),
        "detection_rate": (true_positives / vulns_expected) if vulns_expected else 0.0,
    }


def _target_summary(host: str, group) -> dict:
    agg = aggregate_runs(group)
    return {
        "host": host,
        "runs": len(group),
        "single_run_noisy": agg.single_run_noisy,
        "asset_coverage_mean": agg.asset_coverage_mean,
        "asset_coverage_stdev": agg.asset_coverage_stdev,
        "service_coverage_mean": agg.service_coverage_mean,
        "service_coverage_stdev": agg.service_coverage_stdev,
        "detection_rate_mean": agg.detection_rate_mean,
        "detection_rate_stdev": agg.detection_rate_stdev,
        "weighted_detection_rate_mean": agg.weighted_detection_rate_mean,
        "weighted_detection_rate_stdev": agg.weighted_detection_rate_stdev,
        "false_positives_mean": agg.false_positives_mean,
        "false_positives_stdev": agg.false_positives_stdev,
        "contradictions": sum(s.contradictions for s in group),
        "closed_world": bool(group and group[0].closed_world),
        "run_status": [s.run_status for s in group],
        "errors": sum(1 for s in group if s.error),
        "error": next((s.error for s in group if s.error), None),
    }


def _summary_dict(config: LabConfig, scores, runs: int) -> dict:
    runs = max(1, runs)
    groups = [scores[i * runs:(i + 1) * runs] for i in range(len(config.targets))]
    return {
        "aggregate": _aggregate(scores),
        "runs": runs,
        "targets": [
            _target_summary(t.host, g) for t, g in zip(config.targets, groups)
        ],
    }


def build_report(scores) -> str:
    """Render a Markdown report: a per-run table plus the aggregate metrics.
    Incomplete runs (status != 'complete') are surfaced, not silently passed."""
    agg = _aggregate(scores)
    lines = [
        "# blk engage benchmark",
        "",
        "| host | status | asset cov | service cov | det rate | w-det | TP | FP "
        "| contra | detections | closed-world | error |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for s in scores:
        lines.append(
            f"| {s.host} | {s.run_status or ''} "
            f"| {s.assets_found}/{s.assets_expected} ({s.asset_coverage * 100:.0f}%) "
            f"| {s.services_found}/{s.services_expected} ({s.service_coverage * 100:.0f}%) "
            f"| {s.true_positives}/{s.vulns_expected} ({s.detection_rate * 100:.0f}%) "
            f"| {s.weighted_detection_rate * 100:.0f}% "
            f"| {s.true_positives} | {s.false_positives} | {s.contradictions} "
            f"| {s.detections_total} | {s.closed_world} | {s.error or ''} |"
        )
    lines += [
        "",
        f"- Targets scored: {agg['targets']} ({agg['errors']} errored)",
        f"- Asset coverage: {agg['asset_coverage'] * 100:.1f}% "
        f"({agg['assets_found']}/{agg['assets_expected']})",
        f"- Service coverage: {agg['service_coverage'] * 100:.1f}% "
        f"({agg['services_found']}/{agg['services_expected']})",
        f"- Detection rate: {agg['detection_rate'] * 100:.1f}% "
        f"({agg['true_positives']}/{agg['vulns_expected']})",
        f"- False positives: {agg['false_positives']} "
        f"(contradictions: {agg['contradictions']})",
    ]
    if agg["incomplete_runs"]:
        lines.append(
            f"- WARNING: {agg['incomplete_runs']} run(s) did not complete "
            "(status != 'complete'); treat metrics as partial"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    """CLI: load a lab config, run blk engage per target, score and report.

    Exit code: 2 on a usage error or a config refusal; 1 if any target errored
    or zero targets were scored; else 0.
    """
    parser = argparse.ArgumentParser(
        prog="engage_bench",
        description="Benchmark blk engage recon/detection against a lab config.",
    )
    parser.add_argument("--config", help="path to the operator-supplied lab config JSON")
    parser.add_argument("--recon-goal", help="override the config's recon goal")
    parser.add_argument("--timeout", type=float, help="per-target engage timeout (seconds)")
    parser.add_argument("--runs", type=int, default=1, help="runs per target (default 1)")
    parser.add_argument("--json", action="store_true", help="print a JSON summary")
    parser.add_argument("--report", help="write a Markdown report to this path")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 0

    if not args.config:
        print("error: --config is required", file=sys.stderr)
        return 2

    try:
        config = load_lab_config(args.config)
    except LabConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.recon_goal:
        config = LabConfig(
            recon_goal=args.recon_goal,
            targets=config.targets,
            out_of_scope=config.out_of_scope,
        )

    if args.timeout is not None and args.timeout <= 0:
        print("error: --timeout must be greater than 0", file=sys.stderr)
        return 2
    timeout = args.timeout if args.timeout is not None else _ENGAGE_TIMEOUT
    runs = max(1, args.runs)
    scores = score_batch(
        config, runs=runs, run_fn=lambda cfg, t: run_engage(cfg, t, timeout=timeout)
    )

    # Surface incomplete runs and single-run noise instead of passing silently.
    for s in scores:
        if s.error is None and s.run_status != "complete":
            print(
                f"WARNING: {s.host}: run status {s.run_status!r} is not 'complete'",
                file=sys.stderr,
            )
    if runs == 1:
        print(
            "NOTE: single run (noisy); use --runs N for mean + stdev variance",
            file=sys.stderr,
        )

    if args.json:
        print(json.dumps(_summary_dict(config, scores, runs)))
    else:
        print(build_report(scores))

    if args.report:
        try:
            Path(args.report).write_text(build_report(scores), encoding="utf-8")
        except OSError as exc:
            print(f"error: could not write report: {exc}", file=sys.stderr)
            return 1

    if not scores:
        return 1
    return 1 if any(s.error for s in scores) else 0


if __name__ == "__main__":
    raise SystemExit(main())
