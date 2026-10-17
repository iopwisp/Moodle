"""Assignment-scoped lab context and an additional, restrictive execution guard."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .credentials import redact
from .integrations.base import Capability
from .policy import PolicyEngine, host_of
from .workspace import input_manifest, sha256_file, write_json

PASSPORT_PATH = Path("metadata/lab_passport.json")


class LabPassport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = Field(default=1, ge=1, le=1)
    name: str = Field(min_length=1, max_length=200)
    purpose: str = Field(min_length=1, max_length=1000)
    owner: str = Field(min_length=1, max_length=300)
    source: str = Field(min_length=1)
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    excerpt: str = Field(min_length=1, max_length=4000)
    targets: list[str] = Field(min_length=1, max_length=50)
    actions: list[str] = Field(min_length=1, max_length=100)
    restrictions: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("targets")
    @classmethod
    def exact_hosts(cls, values: list[str]) -> list[str]:
        import ipaddress
        import re

        hosts = []
        for value in values:
            raw = value.strip().casefold()
            try:
                host = str(ipaddress.ip_address(raw.strip("[]")))
            except ValueError:
                host = host_of(raw) or ""
                if host != raw:
                    raise ValueError("Passport targets must not include ports or URL components") from None
            if not host or any(c in value for c in ("*", "/", "@", "?", "#")):
                raise ValueError("Passport targets must be exact hostnames or IPs, without URLs, CIDRs or wildcards")
            try:
                host = str(ipaddress.ip_address(host))
            except ValueError:
                if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host) or ".." in host:
                    raise ValueError("Invalid passport host") from None
            hosts.append(host)
        return sorted(set(hosts))


def _source(workspace: Path, relative: str) -> Path:
    path = (workspace / relative).resolve()
    if Path(relative).is_absolute() or not path.is_relative_to(workspace.resolve()) or not path.is_file():
        raise ValueError("Passport source must be an existing workspace-relative file")
    return path


def _source_text(workspace: Path, source: Path) -> str:
    if source.suffix.lower() in {".txt", ".md", ".json", ".csv"}:
        return source.read_text(encoding="utf-8")
    for entry in input_manifest(workspace):
        if (Path(str(entry.get("workspace_copy", ""))).resolve() == source
                and sha256_file(source) != entry.get("sha256")):
            raise ValueError("Assignment source no longer matches its acquisition hash")
    from .analyzer import _text_from_bytes

    try:
        return _text_from_bytes(source.name, source.read_bytes())
    except Exception as exc:
        raise ValueError("Cannot extract passport source text; supply a workspace text authorization note instead") from exc


def save_passport(workspace: Path, values: dict[str, Any], known_actions: set[str], *, replace: bool = False) -> LabPassport:
    target = workspace / PASSPORT_PATH
    if target.exists() and not replace:
        raise ValueError("Passport already exists; use --replace explicitly to revise it")
    source = _source(workspace, str(values["source"]))
    passport = LabPassport.model_validate({**values, "source_sha256": sha256_file(source)})
    if set(passport.actions) - known_actions:
        raise ValueError("Passport contains unregistered capabilities")
    if passport.excerpt not in _source_text(workspace, source):
        raise ValueError("Passport excerpt was not found verbatim in the source text")
    # Refuse secrets rather than silently changing the authorization quotation.
    payload = passport.model_dump(mode="json")
    if redact(payload) != payload:
        raise ValueError("Passport contains sensitive data; use an authorization excerpt without credentials")
    write_json(target, payload)
    return passport


def load_passport(workspace: Path) -> LabPassport | None:
    path = workspace / PASSPORT_PATH
    if not path.exists():
        return None
    passport = LabPassport.model_validate_json(path.read_text(encoding="utf-8"))
    if sha256_file(_source(workspace, passport.source)) != passport.source_sha256:
        raise ValueError("Passport source hash changed; review the assignment and explicitly replace the passport")
    if passport.excerpt not in _source_text(workspace, _source(workspace, passport.source)):
        raise ValueError("Passport excerpt no longer matches source text")
    return passport


def passport_summary(workspace: Path) -> dict[str, Any]:
    try:
        passport = load_passport(workspace)
    except (ValueError, OSError) as exc:
        return {"present": True, "valid": False, "reason": str(redact(str(exc)))[:300]}
    if passport is None:
        return {"present": False}
    return {"present": True, "valid": True, "name": passport.name, "purpose": passport.purpose[:300],
            "owner": passport.owner, "source": passport.source, "excerpt": passport.excerpt[:500],
            "targets": passport.targets[:10], "target_count": len(passport.targets),
            "actions": passport.actions[:10], "action_count": len(passport.actions),
            "restrictions": [s[:200] for s in passport.restrictions[:5]],
            "scope": "Recorded lab context, not independent proof of authorization; policy still applies"}


def passport_denial(workspace: Path, capability: Capability, parameters: dict[str, Any],
                    policy: PolicyEngine) -> str | None:
    hosts = policy.network_targets(parameters)
    if not capability.network and not hosts:
        return None
    try:
        passport = load_passport(workspace)
    except (ValueError, OSError) as exc:
        return f"Lab passport invalid: {exc}"
    if passport is None:
        return None  # Existing workspaces continue to use the regular policy.
    if capability.name not in passport.actions:
        return f"Lab passport does not include action '{capability.name}'"
    if not hosts:
        return "Lab passport requires explicit target parameters for network operations"
    outside = [h for h in hosts if h not in passport.targets]
    if outside:
        return f"Network target(s) outside lab passport: {', '.join(outside)}"
    denied = [h for h in hosts if not policy.host_allowed(h)]
    if denied:
        return f"Lab passport does not override network policy; target(s) not authorized: {', '.join(denied)}"
    return None
