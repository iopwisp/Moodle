"""Security policy engine evaluated before every capability execution.

The AI planner cannot influence these decisions: they depend only on the
configuration, the capability declaration and the concrete parameters.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .config import AgentConfig
from .integrations.base import Capability

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
_TARGET_KEYS = ("url", "target_url", "target", "host", "hostname", "start_url", "proxy_target")
_HOST_RE = re.compile(r"^[a-z0-9.-]+$|^\[?[0-9a-f:]+\]?$", re.IGNORECASE)


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str = ""
    confirmation_required: bool = False

    @classmethod
    def allow(cls) -> PolicyDecision:
        return cls(True)

    @classmethod
    def deny(cls, reason: str) -> PolicyDecision:
        return cls(False, reason)

    @classmethod
    def confirm(cls, reason: str) -> PolicyDecision:
        return cls(True, reason, confirmation_required=True)


def host_of(value: str) -> str | None:
    """Extract a host name from a URL or bare host[:port] value."""
    text = value.strip()
    if not text:
        return None
    parsed = urlparse(text if "://" in text else f"//{text}", scheme="http")
    host = (parsed.hostname or "").casefold()
    return host or None


def is_local_host(host: str) -> bool:
    if host in LOCAL_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class PolicyEngine:
    def __init__(self, config: AgentConfig, extra_targets: set[str] | None = None) -> None:
        self.config = config
        self.targets = config.authorized_targets(extra_targets)

    def host_allowed(self, host: str) -> bool:
        network = self.config.policy.network
        if is_local_host(host):
            return network.localhost
        if not network.authorized_targets_only:
            return True
        if host in self.targets:
            return True
        # Only explicit wildcard entries ("*.lab.local") authorize sub-domains.
        return any(target.startswith("*.") and host.endswith(target[1:]) for target in self.targets)

    def url_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        return self.host_allowed(parsed.hostname.casefold())

    def network_targets(self, parameters: dict[str, Any]) -> list[str]:
        hosts: list[str] = []
        for key in _TARGET_KEYS:
            value = parameters.get(key)
            if isinstance(value, str) and value.strip():
                host = host_of(value)
                if host:
                    hosts.append(host)
        return hosts

    def check(self, capability: Capability, parameters: dict[str, Any]) -> PolicyDecision:
        tool_policy = self.config.policy.tools.get(capability.tool)
        if tool_policy is not None and not tool_policy.allowed:
            return PolicyDecision.deny(f"Tool '{capability.tool}' is disabled by policy.")

        if capability.risk == "unsafe" and capability.tool == "powershell" and not self.config.policy.powershell.arbitrary:
            return PolicyDecision.deny(
                "Arbitrary PowerShell is disabled (policy.powershell.arbitrary=false). "
                "Enable it explicitly in config.yaml and approve each command."
            )

        for host in self.network_targets(parameters):
            if not _HOST_RE.match(host) or not self.host_allowed(host):
                return PolicyDecision.deny(
                    f"Network target '{host}' is not authorized. Add it to "
                    "policy.network.authorized_targets or pass --allowed-target before execution."
                )

        if capability.risk in self.config.policy.require_confirmation_for_risk:
            return PolicyDecision.confirm(f"{capability.name} is marked {capability.risk}; user approval required.")
        if tool_policy is not None and tool_policy.require_confirmation:
            return PolicyDecision.confirm(f"Policy requires approval before using {capability.tool}.")
        return PolicyDecision.allow()
