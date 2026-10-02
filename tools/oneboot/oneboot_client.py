#!/usr/bin/env python3
"""Dependency-free client for the OneBoot network-install console API.

OneBoot is the internal PXE provisioning console at ``oneboot.netisdev.com``
(see ``docs/ONEBOOT_LAB.md``).  Its management API lives under ``/api/v1`` and
is unauthenticated on the lab network; it is *not* part of the published
``pulse-v1`` read-only contract (``/openapi.yaml``), so field names are asserted
here explicitly and the client fails loudly rather than silently drifting.

Everything is stdlib.  Import it:

    from oneboot_client import OneBoot
    ob = OneBoot("https://oneboot.netisdev.com")
    for s in ob.sources():
        print(s["id"], s["filename"])

or use it from the shell:

    tools/oneboot/oneboot_client.py status
    tools/oneboot/oneboot_client.py sources --arch aarch64
    tools/oneboot/oneboot_client.py selftest
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class OneBootError(RuntimeError):
    """Raised for any non-2xx response or an unparseable body."""


# OneBoot's `/api/v1/status` doubles as a version probe.  Bump when a field the
# client relies on is renamed (the API is documented as "may change").
EXPECTED_STATUS_KEYS = {"success", "dhcp_mode", "http_port", "install_stats"}


@dataclasses.dataclass
class OneBoot:
    """A thin, explicit wrapper around the OneBoot management API."""

    base_url: str
    timeout: float = 30.0

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")

    # -- transport ---------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        raw_body: bytes | None = None,
        content_type: str | None = None,
        parse: bool = True,
    ) -> Any:
        url = self.base_url + path
        if params:
            # None values are dropped so callers can pass optional query args.
            clean = {k: v for k, v in params.items() if v is not None}
            if clean:
                url += "?" + urllib.parse.urlencode(clean)

        headers: dict[str, str] = {"Accept": "application/json, */*"}
        data: bytes | None = None
        if json_body is not None:
            data = json.dumps(json_body).encode()
            headers["Content-Type"] = "application/json"
        elif raw_body is not None:
            data = raw_body
            if content_type:
                headers["Content-Type"] = content_type

        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
                status = resp.status
        except urllib.error.HTTPError as exc:  # pragma: no cover - network path
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise OneBootError(f"{method} {path} -> HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:  # pragma: no cover - network path
            raise OneBootError(f"{method} {path} -> unreachable: {exc.reason}") from exc

        if status >= 300:  # urllib follows redirects; this is a safety net
            raise OneBootError(f"{method} {path} -> HTTP {status}")
        if not parse:
            return body.decode("utf-8", "replace")
        if not body:
            return None
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise OneBootError(
                f"{method} {path} -> non-JSON body ({exc}): {body[:200]!r}"
            ) from exc

    def _get(self, path: str, **kw: Any) -> Any:
        return self._request("GET", path, **kw)

    def _post(self, path: str, **kw: Any) -> Any:
        return self._request("POST", path, **kw)

    def _put(self, path: str, **kw: Any) -> Any:
        return self._request("PUT", path, **kw)

    # -- read endpoints ----------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Service state, DHCP pools, ISO counts and recent install events."""
        return self._get("/api/v1/status")

    def sources(self) -> list[dict[str, Any]]:
        """Every scanned ISO with arch / boot_style / kickstart support."""
        return self._get("/api/v1/sources").get("sources", [])

    def find_source(self, source_id: str) -> dict[str, Any] | None:
        for src in self.sources():
            if src.get("id") == source_id:
                return src
        return None

    def clients(self) -> list[dict[str, Any]]:
        """DHCP leases seen by OneBoot (mac / ip / hostname / session)."""
        return self._get("/api/v1/clients").get("clients", [])

    def client_for_mac(self, mac: str) -> dict[str, Any] | None:
        want = mac.lower().replace("-", ":")
        for c in self.clients():
            if c.get("mac", "").lower() == want:
                return c
        return None

    def sessions(self) -> list[dict[str, Any]]:
        return self._get("/api/v1/sessions").get("sessions", [])

    def install_events(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._get(
            "/api/v1/install-events", params={"limit": limit}
        ).get("events", [])

    def kickstarts(self) -> dict[str, list[str]]:
        """Map of source_id -> [kickstart filenames]."""
        return self._get("/api/v1/kickstart").get("kickstarts", {})

    def kickstart_files(self, source_id: str) -> list[str]:
        return self._get(f"/api/v1/kickstart/{source_id}").get("files", [])

    def get_kickstart(self, source_id: str, filename: str) -> str:
        return self._get(f"/api/v1/kickstart/{source_id}/{filename}").get("content", "")

    def kickstart_templates(self, iso_id: str = "") -> list[dict[str, Any]]:
        return self._get(
            "/api/v1/kickstart/templates", params={"iso_id": iso_id or None}
        ).get("templates", [])

    def menu_preview(self) -> str:
        return self._get("/api/v1/menu/preview").get("content", "")

    def dhcp_settings(self) -> dict[str, Any]:
        return self._get("/api/v1/settings/dhcp")

    def boot_profiles(self, source_id: str) -> dict[str, Any]:
        return self._get(f"/api/v1/sources/{source_id}/boot-profiles")

    def boot_menu(self, source_id: str, mac: str) -> str:
        """iPXE menu that offers manual vs. per-kickstart installs."""
        return self._get(
            f"/boot/{source_id}", params={"mac": _dashed_mac(mac)}, parse=False
        )

    def boot_script(self, source_id: str, mac: str, ks: str | None = None) -> str:
        """Concrete iPXE kernel/initrd/inst.ks lines for one machine."""
        return self._get(
            f"/boot/{source_id}/go",
            params={"mac": _dashed_mac(mac), "ks": ks},
            parse=False,
        )

    # -- write endpoints (used by the release pipeline) --------------------

    def save_kickstart(self, source_id: str, filename: str, content: str) -> Any:
        """Create/overwrite ``filename`` under ``source_id`` (PUT, JSON)."""
        return self._put(
            f"/api/v1/kickstart/{source_id}/{filename}", json_body={"content": content}
        )

    def delete_kickstart(self, source_id: str, filename: str) -> Any:
        return self._request("DELETE", f"/api/v1/kickstart/{source_id}/{filename}")

    def upload_kickstart(self, source_id: str, local_path: str) -> Any:
        """Multipart upload of a kickstart file (mirrors the web UI)."""
        with open(local_path, "rb") as fh:
            payload = fh.read()
        boundary = "----onebootboundary8f2a1c"
        name = urllib.parse.quote(local_path.rsplit("/", 1)[-1])
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{name}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode() + payload + f"\r\n--{boundary}--\r\n".encode()
        return self._post(
            f"/api/v1/kickstart/upload/{source_id}",
            raw_body=body,
            content_type=f"multipart/form-data; boundary={boundary}",
        )

    def mount_source(self, source_id: str) -> Any:
        return self._post(f"/api/v1/sources/{source_id}/mount")

    def unmount_source(self, source_id: str) -> Any:
        return self._post(f"/api/v1/sources/{source_id}/unmount")

    def generate_menu(self) -> Any:
        return self._post("/api/v1/menu/generate")

    def reset_dhcp(self) -> Any:
        return self._post("/api/v1/clients/reset-dhcp")

    def disconnect_client(self, mac: str) -> Any:
        return self._post(f"/api/v1/clients/{_dashed_mac(mac)}/disconnect")

    def cleanup_sessions(self) -> Any:
        return self._post("/api/v1/sessions/cleanup")

    def restart_service(self) -> Any:
        return self._post("/api/v1/service/restart")

    def update_dhcp_settings(self, settings: dict[str, Any]) -> Any:
        return self._put("/api/v1/settings/dhcp", json_body=settings)

    # -- diagnostics -------------------------------------------------------

    def selftest(self) -> list[str]:
        """Read-only probe of the endpoints the pipeline depends on.

        Returns human-readable check lines; raises ``OneBootError`` on the first
        hard failure.  Deliberately never calls a write endpoint, so it is safe
        to run against the shared production console.
        """
        lines: list[str] = []

        def check(name: str, ok: bool, detail: str) -> None:
            lines.append(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}")

        status = self.status()
        missing = EXPECTED_STATUS_KEYS - set(status)
        check(
            "status",
            status.get("success") is True and not missing,
            f"dhcp_mode={status.get('dhcp_mode')} http_port={status.get('http_port')}"
            + (f" missing={sorted(missing)}" if missing else ""),
        )

        srcs = self.sources()
        archs = sorted({s.get("architecture", "?") for s in srcs})
        check("sources", len(srcs) > 0, f"{len(srcs)} ISO(s), archs={archs}")

        ks = self.kickstarts()
        ks_count = sum(len(v) for v in ks.values())
        check("kickstart", isinstance(ks, dict), f"{ks_count} kickstart(s) on {len(ks)} source(s)")

        evs = self.install_events(limit=1)
        check("install-events", isinstance(evs, list), f"{len(evs)} event(s) sampled")

        cs = self.clients()
        check("clients", isinstance(cs, list), f"{len(cs)} lease(s)")

        # Preview the boot chain for the first source that has a kickstart.
        target = next(((sid, files[0]) for sid, files in ks.items() if files), None)
        if target:
            sid, ksfile = target
            script = self.boot_script(sid, "52:54:00:11:22:33", ks=ksfile)
            ok = "inst.ks=" in script and "/kickstart/" in script
            check("boot-script", ok, f"{sid} -> {'inst.ks present' if ok else script[:80]!r}")
        else:
            check("boot-script", False, "no kickstart to preview")

        return lines


def _dashed_mac(mac: str) -> str:
    """OneBoot's iPXE routes take ``aa-bb-cc-dd-ee-ff``."""
    return mac.lower().replace(":", "-")


# -- CLI -------------------------------------------------------------------


def _cmd_status(ob: OneBoot, _args: argparse.Namespace) -> int:
    s = ob.status()
    print(json.dumps({k: v for k, v in s.items() if k != "recent_events"},
                     indent=2, ensure_ascii=False))
    return 0


def _cmd_sources(ob: OneBoot, args: argparse.Namespace) -> int:
    for src in ob.sources():
        if args.arch and src.get("architecture") != args.arch:
            continue
        ks = "ks" if src.get("kickstart_enabled") else "--"
        print(f"{src['id']:<60} {src.get('architecture','?'):<10} "
              f"{src.get('boot_style','?'):<10} {ks:<3} "
              f"{src.get('os_label',''):<12} {src.get('filename','')}")
    return 0


def _cmd_kickstarts(ob: OneBoot, args: argparse.Namespace) -> int:
    for sid, files in sorted(ob.kickstarts().items()):
        if args.source and sid != args.source:
            continue
        print(f"{sid}: {', '.join(files) if files else '(none)'}")
    return 0


def _cmd_events(ob: OneBoot, args: argparse.Namespace) -> int:
    for ev in ob.install_events(limit=args.limit):
        print(f"{ev.get('timestamp',''):<22} {ev.get('outcome',''):<8} "
              f"{ev.get('mac',''):<18} {ev.get('source_id',''):<45} {ev.get('reason','')}")
    return 0


def _cmd_selftest(ob: OneBoot, _args: argparse.Namespace) -> int:
    lines = ob.selftest()
    for line in lines:
        print(line)
    return 0 if all(line.startswith("PASS") for line in lines) else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default="https://oneboot.netisdev.com",
                        help="OneBoot console base URL")
    parser.add_argument("--timeout", type=float, default=30.0)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("status", help="print service status")
    p.set_defaults(func=_cmd_status)

    p = sub.add_parser("sources", help="list ISO sources")
    p.add_argument("--arch", help="filter by architecture, e.g. aarch64")
    p.set_defaults(func=_cmd_sources)

    p = sub.add_parser("kickstarts", help="list kickstart files")
    p.add_argument("--source", help="filter by source id")
    p.set_defaults(func=_cmd_kickstarts)

    p = sub.add_parser("events", help="recent install events")
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=_cmd_events)

    p = sub.add_parser("selftest", help="read-only probe of the pipeline's endpoints")
    p.set_defaults(func=_cmd_selftest)

    args = parser.parse_args(argv)
    ob = OneBoot(args.base_url, timeout=args.timeout)
    try:
        return args.func(ob, args)
    except OneBootError as exc:
        print(f"oneboot: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
