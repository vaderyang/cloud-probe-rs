#!/usr/bin/env python3
"""Drive OneBoot to install a target OS and verify a released build on it.

This is the lab half of the cross-platform release pipeline.  GitHub-hosted
runners cannot reach OneBoot (it is internal-only), so this runs on a
self-hosted runner on the corporate network.  It:

  1. stages the release tarball + ``on_target_smoke.sh`` on a local HTTP server;
  2. renders a kickstart/autoinstall whose ``%post`` (or ``late-commands``)
     fetches that payload onto the freshly installed machine and runs it;
  3. uploads the kickstart to OneBoot (``--apply``);
  4. optionally power-cycles the target into PXE via its BMC;
  5. collects the machine-readable verdict (callback POST or SSH pull) and
     writes a JUnit report for CI.

Nothing is written to the shared OneBoot server and no machine is touched
unless ``--apply`` is given; the default is a dry run that prints the
kickstart and the exact boot URL.

See ``docs/ONEBOOT_LAB.md`` for the inventory format and the runbook.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import http.server
import json
import pathlib
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from oneboot_client import OneBoot, OneBootError

RESULT_SCHEMA = "cprs-on-target-smoke-v1"

# ---------------------------------------------------------------------------
# Payload staging + result receiver
# ---------------------------------------------------------------------------


class StageServer:
    """Serve the staged payload and receive the target's result POST.

    Kept deliberately tiny: one directory listing is enough, and the only
    write endpoint is ``POST /result``.
    """

    def __init__(self, root: pathlib.Path, host: str, port: int) -> None:
        self.root = root
        self.host = host
        self.port = port
        self.result: dict[str, Any] | None = None
        self._cond = threading.Condition()
        outer = self

        class Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *a: Any, **kw: Any) -> None:
                super().__init__(*a, directory=str(root), **kw)

            # Named `format` by the http.server base class.
            def log_message(self, format: str, *args: Any) -> None:
                sys.stderr.write(f"[stage] {format % args}\n")

            # Named `do_POST` by the http.server base class.
            def do_POST(self) -> None:
                if not self.path.startswith("/result"):
                    self.send_error(404)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                try:
                    outer.result = json.loads(body)
                    with outer._cond:
                        outer._cond.notify_all()
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")
                except json.JSONDecodeError:
                    self.send_error(400, "invalid JSON")

        self._httpd = http.server.ThreadingHTTPServer((host, port), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    # `typing.Self` is 3.11+; the lab runner may be on 3.10, so annotate the
    # class directly (valid as a string under `from __future__ import
    # annotations`).
    def __enter__(self) -> StageServer:  # noqa: PYI034
        self._thread.start()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    def wait_result(self, timeout: float) -> dict[str, Any] | None:
        deadline = time.monotonic() + timeout
        with self._cond:
            while self.result is None:
                left = deadline - time.monotonic()
                if left <= 0:
                    return None
                self._cond.wait(timeout=min(left, 5.0))
        return self.result


def advertise_host(explicit: str | None) -> str:
    """Return a host/IP the target can dial back to for the staged payload."""
    if explicit:
        return explicit
    # Best-effort: the source address the kernel would use to reach OneBoot.
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("10.1.1.182", 80))
        return probe.getsockname()[0]
    finally:
        probe.close()


# ---------------------------------------------------------------------------
# Kickstart / autoinstall rendering
# ---------------------------------------------------------------------------

_SMOKE_POST = """\
%post --interpreter=/bin/bash --log=/root/cprs-ks-post.log
echo "=== cloud-probe-rs release verification ==="
BASE="{base}"
export ARTIFACT_URL="$BASE/{archive}"
export ARTIFACT_SHA256="{sha256}"
export CALLBACK_URL="{callback}"
export RESULT_FILE=/root/cprs-smoke/result.json
export FRAMES="{frames}"
mkdir -p /root/cprs-smoke
# Best-effort: old distros (CentOS 7) ship no python3; the veth injector needs
# it.  Failure is non-fatal - the capture check just SKIPs.
if ! command -v python3 >/dev/null 2>&1; then
  (yum install -y epel-release >/dev/null 2>&1 && \\
     yum install -y python3 >/dev/null 2>&1) || true
fi
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$BASE/on_target_smoke.sh" -o /root/cprs-smoke.sh
elif command -v wget >/dev/null 2>&1; then
  wget -qO /root/cprs-smoke.sh "$BASE/on_target_smoke.sh"
fi
chmod +x /root/cprs-smoke.sh
bash /root/cprs-smoke.sh || echo "smoke reported failures (see /root/cprs-smoke/result.json)"
%end
"""


def render_redhat(base: str, archive: str, sha256: str, callback: str, frames: int) -> str:
    return f"""\
# cloud-probe-rs release verification (OneBoot lab) - redhat family
text
skipx
reboot
lang en_US.UTF-8
keyboard us
timezone Asia/Shanghai --utc
rootpw --plaintext rootroot
network --bootproto=dhcp --device=link --activate
firewall --disabled
selinux --disabled
services --enabled=sshd
bootloader --location=mbr
zerombr
clearpart --all --initlabel
autopart --type=lvm

%packages --ignoremissing
@core
curl
tar
gzip
iproute
%end

{_SMOKE_POST.format(base=base, archive=archive, sha256=sha256, callback=callback, frames=frames)}"""


def render_ubuntu(base: str, archive: str, sha256: str, callback: str, frames: int) -> str:
    smoke = (
        "mkdir -p /root/cprs-smoke && "
        f"curl -fsSL {base}/on_target_smoke.sh -o /root/cprs-smoke.sh && "
        "env "
        f"ARTIFACT_URL={base}/{archive} "
        f"ARTIFACT_SHA256={sha256} "
        f"CALLBACK_URL={callback} "
        "RESULT_FILE=/root/cprs-smoke/result.json "
        f"FRAMES={frames} "
        "bash /root/cprs-smoke.sh || true"
    )
    return f"""\
#cloud-config
# cloud-probe-rs release verification (OneBoot lab) - ubuntu autoinstall
autoinstall:
  version: 1
  locale: en_US.UTF-8
  keyboard:
    layout: us
  ssh:
    install-server: true
    allow-pw: true
  user-data:
    disable_root: false
    ssh_pwauth: true
  network:
    version: 2
    ethernets:
      default:
        match:
          name: "e*"
        dhcp4: true
        optional: true
  storage:
    layout:
      name: lvm
      sizing-policy: all
    swap:
      size: 0
  late-commands:
    - "curtin in-target --target=/target -- usermod -p '$6$oneboot$7FSGbX9DFZd4ODOVWY6.1VPZm8m1dsvk3rmECbQMnTcFcEt6W7oXRcplFzsTSXXe7RQPxGIqfn33T2AM1eRV.1' root"
    - "curtin in-target --target=/target -- passwd -u root || true"
    - "curtin in-target --target=/target -- sh -c 'mkdir -p /etc/ssh/sshd_config.d && printf \\"PermitRootLogin yes\\\\nPasswordAuthentication yes\\\\n\\" > /etc/ssh/sshd_config.d/99-oneboot.conf'"
    - "curtin in-target --target=/target -- sh -c {shlex.quote(smoke)}"
"""


def render_kickstart(boot_style: str, **kw: Any) -> str:
    if boot_style in ("redhat",):
        return render_redhat(**kw)
    if boot_style in ("casper", "ubuntu"):
        return render_ubuntu(**kw)
    raise SystemExit(
        f"boot_style={boot_style!r} is not supported yet "
        "(redhat families and ubuntu autoinstall are)"
    )


# ---------------------------------------------------------------------------
# BMC control
# ---------------------------------------------------------------------------


def ipmi(args: argparse.Namespace, *cmd: str) -> subprocess.CompletedProcess[str]:
    base = ["ipmitool", "-I", args.bmc_interface, "-H", args.bmc_host]
    if args.bmc_user:
        base += ["-U", args.bmc_user]
    if args.bmc_pass:
        base += ["-P", args.bmc_pass]
    return subprocess.run(base + list(cmd), capture_output=True, text=True, check=False)


def trigger_ipmi(args: argparse.Namespace) -> None:
    opts = "options=efiboot" if args.efi else ""
    cmd = ["chassis", "bootdev", "pxe"] + ([opts] if opts else [])
    r = ipmi(args, *cmd)
    print(f"[bmc] bootdev pxe {opts}: {r.returncode} {r.stdout.strip()}")
    r = ipmi(args, "power", "reset")
    print(f"[bmc] power reset: {r.returncode} {r.stdout.strip()}")
    if r.returncode != 0:
        raise SystemExit(f"ipmitool power reset failed: {r.stderr.strip()}")


def trigger_oneboot_api(args: argparse.Namespace, src: dict[str, Any]) -> None:
    """Ask the console to bind this MAC's next boot (docs/ONEBOOT_LAB.md §6.1).

    `POST /api/v1/boot/next {mac, source, ks}` is proposed but not implemented on
    the console yet (`cloud-probe-rs-2hs.4`), so the common outcome today is an
    HTTP 404. That is reported as a failure with the fallback spelled out rather
    than silently degrading to a manual boot nobody performs.
    """
    try:
        OneBoot(args.oneboot).boot_next(args.mac, args.source, args.kickstart_name)
    except OneBootError as exc:
        raise SystemExit(
            f"--trigger oneboot-api needs the per-MAC binding endpoint, which this "
            f"console does not offer yet: {exc}\n"
            f"Use --trigger manual (pick {args.kickstart_name} in the menu for "
            f"{src['filename']}), or --trigger ipmi, or land the §6.1 endpoint first."
        ) from exc
    print(f"[oneboot] bound the next boot of {args.mac} to {args.source} "
          f"(ks={args.kickstart_name})")


# ---------------------------------------------------------------------------
# Result collection
# ---------------------------------------------------------------------------


def pull_result_ssh(args: argparse.Namespace) -> dict[str, Any] | None:
    if not args.ssh_host:
        return None
    target = f"{args.ssh_user}@{args.ssh_host}"
    cmd = ["ssh", "-p", str(args.ssh_port), "-o", "BatchMode=yes",
           "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5"]
    if args.ssh_key:
        cmd += ["-i", args.ssh_key]
    # `true` makes the remote exit 0 even when the file does not exist yet.
    cmd += [target, "cat /root/cprs-smoke/result.json 2>/dev/null || true"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# JUnit + summary
# ---------------------------------------------------------------------------


def write_junit(path: pathlib.Path, target_name: str, result: dict[str, Any] | None,
                error: str | None) -> None:
    import xml.etree.ElementTree as ET

    suite = ET.Element("testsuite", name=f"oneboot-lab[{target_name}]")
    if result is None:
        case = ET.SubElement(suite, "testcase", name="oneboot-lab")
        fail = ET.SubElement(case, "error", message=error or "no result collected")
        fail.text = error or "no result collected"
    else:
        for c in result.get("checks", []):
            case = ET.SubElement(suite, "testcase", name=c["name"])
            if c["status"] == "FAIL":
                f = ET.SubElement(case, "failure", message=c.get("detail", ""))
                f.text = c.get("detail", "")
            elif c["status"] == "SKIP":
                ET.SubElement(case, "skipped", message=c.get("detail", ""))
            ET.SubElement(case, "system-out").text = c.get("detail", "")
    path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)


def print_summary(target_name: str, result: dict[str, Any] | None, error: str | None) -> int:
    if result is None:
        print(f"FAIL {target_name}: {error}")
        return 1
    print(f"--- {target_name} ({result.get('os','?')}, {result.get('arch','?')}, "
          f"{result.get('glibc','?')}) ---")
    for c in result.get("checks", []):
        print(f"  [{c['status']}] {c['name']}: {c.get('detail','')}")
    return 0 if result.get("ok") else 1


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def _stage(args: argparse.Namespace) -> tuple[pathlib.Path, str, str]:
    stage = pathlib.Path(args.stage_dir).resolve()
    stage.mkdir(parents=True, exist_ok=True)
    archive = pathlib.Path(args.artifact)
    if not archive.is_file():
        raise SystemExit(f"artifact not found: {archive}")
    dest = stage / archive.name
    if archive.resolve() != dest.resolve():
        shutil.copyfile(archive, dest)
    # Keep our own smoke payload next to the artifacts.
    smoke = pathlib.Path(__file__).resolve().parent / "on_target_smoke.sh"
    (stage / "on_target_smoke.sh").write_bytes(smoke.read_bytes())
    sha256 = args.sha256 or _sha256(dest)
    return stage, dest.name, sha256


def _sha256(path: pathlib.Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def cmd_plan(args: argparse.Namespace) -> int:
    base = f"http://{args.serve_host}:{args.serve_port}"
    _, name, sha256 = _stage(args)
    ks = render_kickstart(
        args.boot_style, base=base, archive=name, sha256=sha256,
        callback=f"{base}/result", frames=args.frames,
    )
    if args.dump_kickstart:
        pathlib.Path(args.dump_kickstart).write_text(ks)
        print(f"[plan] wrote kickstart to {args.dump_kickstart}", file=sys.stderr)
    print(ks)
    print(f"# --- would save to OneBoot as "
          f"/api/v1/kickstart/{args.source}/{args.kickstart_name}", file=sys.stderr)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    host = advertise_host(args.serve_host)
    base = f"http://{host}:{args.serve_port}"
    stage, name, sha256 = _stage(args)
    callback = f"{base}/result"

    kickstart = render_kickstart(
        args.boot_style, base=base, archive=name, sha256=sha256,
        callback=callback, frames=args.frames,
    )
    if args.dump_kickstart:
        pathlib.Path(args.dump_kickstart).write_text(kickstart)
        print(f"[plan] wrote kickstart to {args.dump_kickstart}")

    ob = OneBoot(args.oneboot)
    src = ob.find_source(args.source)
    if src is None:
        raise SystemExit(f"source {args.source!r} not found on {args.oneboot}")
    print(f"[plan] source {args.source}: {src['filename']} "
          f"({src.get('architecture')}, boot_style={src.get('boot_style')})")

    if not args.apply:
        print("[dry-run] not uploading the kickstart and not touching any machine.")
        print(f"[dry-run] re-run with --apply to PUT "
              f"/api/v1/kickstart/{args.source}/{args.kickstart_name}")
        print(f"[dry-run] staged payload: {base}/{name}")
        if args.trigger == "oneboot-api":
            print(f"[dry-run] would POST {args.oneboot}/api/v1/boot/next "
                  f"{{mac: {args.mac}, source: {args.source}, "
                  f"ks: {args.kickstart_name}}} (needs the §6.1 endpoint; "
                  f"cloud-probe-rs-2hs.4)")
        print(f"[dry-run] boot URL (select this kickstart in the PXE menu): "
              f"{args.oneboot}/boot/{args.source}/go?mac={args.mac.replace(':', '-')}"
              f"&ks={urllib.parse.quote(args.kickstart_name)}")
        return 0

    # 1. Upload the kickstart.
    ob.save_kickstart(args.source, args.kickstart_name, kickstart)
    print(f"[oneboot] saved kickstart {args.kickstart_name} for {args.source}")

    with StageServer(stage, args.serve_bind, args.serve_port) as server:
        print(f"[stage] serving {stage} on {base} (callback {callback})")

        # 2. Trigger the target.
        started = _dt.datetime.now(_dt.timezone.utc)
        if args.trigger == "ipmi":
            trigger_ipmi(args)
        elif args.trigger == "oneboot-api":
            trigger_oneboot_api(args, src)
        elif args.trigger == "manual":
            print(f"[manual] power on {args.mac} with PXE boot and select "
                  f"{args.kickstart_name} in the OneBoot menu for "
                  f"{src['filename']}. Waiting up to {args.timeout}s ...")
        # else: 'none' - the machine is already booting.

        # 3. Wait for the result (callback first, SSH fallback).
        deadline = time.monotonic() + args.timeout
        result = None
        while time.monotonic() < deadline:
            result = server.wait_result(timeout=5.0)
            if result is not None:
                break
            if args.ssh_host:
                result = pull_result_ssh(args)
                if result is not None:
                    print("[collect] result pulled over SSH")
                    break
        err = None if result else f"no result within {args.timeout}s"

    # 4. Record the install event for the audit trail.
    if args.install_events_out:
        try:
            events = [e for e in ob.install_events(limit=100)
                      if e.get("mac", "").lower() == args.mac.lower()]
            payload = {"target": args.target_name, "since": started.isoformat(),
                       "events": events}
            pathlib.Path(args.install_events_out).write_text(json.dumps(payload, indent=2))
        except OneBootError as exc:
            print(f"[warn] could not fetch install events: {exc}", file=sys.stderr)

    if args.result_out and result is not None:
        pathlib.Path(args.result_out).write_text(json.dumps(result, indent=2))
    if args.junit_out:
        write_junit(pathlib.Path(args.junit_out), args.target_name, result, err)

    return print_summary(args.target_name, result, err)


def cmd_verify_ssh(args: argparse.Namespace) -> int:
    """Run the smoke payload over SSH on an already-installed host (no PXE)."""
    remote = f"{args.ssh_user}@{args.ssh_host}"
    ssh = ["ssh", "-p", str(args.ssh_port), "-o", "BatchMode=yes",
           "-o", "StrictHostKeyChecking=no"]
    scp = ["scp", "-P", str(args.ssh_port), "-o", "BatchMode=yes",
           "-o", "StrictHostKeyChecking=no"]
    if args.ssh_key:
        ssh += ["-i", args.ssh_key]
        scp += ["-i", args.ssh_key]

    stage, name, sha256 = _stage(args)
    base = f"http://{advertise_host(args.serve_host)}:{args.serve_port}"
    with StageServer(stage, args.serve_bind, args.serve_port) as server:
        print(f"[stage] serving {stage} on {base}")
        subprocess.run(scp + [str(stage / "on_target_smoke.sh"), f"{remote}:/tmp/on_target_smoke.sh"],
                       check=True)
        cmd = (
            "env "
            f"ARTIFACT_URL='{base}/{name}' ARTIFACT_SHA256='{sha256}' "
            f"CALLBACK_URL='{base}/result' RESULT_FILE=/tmp/cprs-result.json "
            f"FRAMES='{args.frames}' bash /tmp/on_target_smoke.sh; "
            "cat /tmp/cprs-result.json"
        )
        proc = subprocess.run(ssh + [remote, cmd], capture_output=True, text=True,
                              check=False)
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        result = server.wait_result(timeout=10.0)
        if result is None:
            # The remote cat was our stdout; recover the JSON tail if present.
            try:
                result = json.loads(proc.stdout[proc.stdout.index("{"):])
            except (ValueError, json.JSONDecodeError):
                result = None
    err = None if result else "could not parse remote result"
    if args.result_out and result is not None:
        pathlib.Path(args.result_out).write_text(json.dumps(result, indent=2))
    if args.junit_out:
        write_junit(pathlib.Path(args.junit_out), args.target_name, result, err)
    return print_summary(args.target_name, result, err)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--oneboot", default="https://oneboot.netisdev.com")
    common.add_argument("--artifact", required=True,
                        help="local cloud-probe-rs-<target>.tar.gz")
    common.add_argument("--sha256", help="expected sha256 (default: compute)")
    common.add_argument("--target-name", default="target")
    common.add_argument("--source", help="OneBoot source id, e.g. centos_7_9_x86_64_dvd_2009")
    common.add_argument("--boot-style", default="redhat", choices=["redhat", "casper"])
    common.add_argument("--kickstart-name", default="cprs-verify.cfg")
    common.add_argument("--mac", default="", help="target NIC MAC (aa:bb:cc:dd:ee:ff)")
    common.add_argument("--frames", type=int, default=2000)
    common.add_argument("--apply", action="store_true",
                        help="actually upload the kickstart and act on the target")
    common.add_argument("--trigger", default="manual",
                        choices=["manual", "ipmi", "oneboot-api", "none"])
    common.add_argument("--efi", action="store_true", help="BMC: request EFI PXE")
    common.add_argument("--stage-dir",
                        default=str(pathlib.Path(tempfile.gettempdir()) / "cprs-lab-stage"))
    common.add_argument("--dump-kickstart", help="write the rendered kickstart here")

    net = common.add_argument_group("payload server")
    net.add_argument("--serve-host", help="advertised IP (default: auto-detect)")
    # Empty host == all interfaces; the target machines are on a different lab
    # subnet, so the payload server must not be loopback-only.
    net.add_argument("--serve-bind", default="")
    net.add_argument("--serve-port", type=int, default=8000)

    bmc = common.add_argument_group("BMC")
    bmc.add_argument("--bmc-host")
    bmc.add_argument("--bmc-user")
    bmc.add_argument("--bmc-pass")
    bmc.add_argument("--bmc-interface", default="lanplus")

    ssh = common.add_argument_group("SSH result pull")
    ssh.add_argument("--ssh-host")
    ssh.add_argument("--ssh-user", default="root")
    ssh.add_argument("--ssh-port", type=int, default=22)
    ssh.add_argument("--ssh-key")

    out = common.add_argument_group("outputs")
    out.add_argument("--timeout", type=float, default=3600.0)
    out.add_argument("--junit-out")
    out.add_argument("--result-out")
    out.add_argument("--install-events-out")

    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("plan", parents=[common], help="render the kickstart and show the dry-run plan")
    sub.add_parser("run", parents=[common], help="stage, upload, trigger and collect")
    sub.add_parser("verify-ssh", parents=[common],
                   help="run the smoke payload over SSH (no PXE)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.source and args.command in ("run",):
        raise SystemExit("--source is required for `run`")
    if args.trigger == "ipmi" and args.command == "run" and not args.bmc_host:
        raise SystemExit("--bmc-host is required for --trigger ipmi")
    if args.command == "verify-ssh" and not args.ssh_host:
        raise SystemExit("--ssh-host is required for verify-ssh")
    try:
        return {"plan": cmd_plan, "run": cmd_run, "verify-ssh": cmd_verify_ssh}[args.command](args)
    except OneBootError as exc:
        print(f"oneboot: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
