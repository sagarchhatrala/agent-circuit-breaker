"""Network egress and SSRF guard."""

from __future__ import annotations

import ipaddress
import socket
from typing import Iterable
from urllib.parse import urlparse

from agent_circuit_breaker.core.context import AgentContext
from agent_circuit_breaker.core.results import GuardResult


class NetworkEgressGuard:
    """Block private, loopback, link-local, and metadata network targets."""

    guard_id = "network_egress_guard"

    def __init__(self, blocked_hosts: Iterable[str] = ("169.254.169.254",)) -> None:
        self.blocked_hosts = {host.lower() for host in blocked_hosts}

    async def evaluate(self, context: AgentContext) -> GuardResult:
        urls = _urls_from_context(context)
        if not urls:
            return GuardResult.unknown(self.guard_id, "no URL")

        for url in urls:
            parsed = urlparse(_with_scheme(url))
            host = (parsed.hostname or "").lower()
            if not host:
                continue
            if host in self.blocked_hosts:
                return GuardResult.deny(self.guard_id, f"blocked metadata host {host}", "CRITICAL")
            verdict = _host_is_private(host)
            if verdict:
                return GuardResult.deny(self.guard_id, f"blocked private network target {host}", "HIGH")

        return GuardResult.allow(self.guard_id, "network targets passed egress policy")


def _urls_from_context(context: AgentContext) -> list[str]:
    value = context.tool_args.get("url")
    if isinstance(value, str):
        return [value]
    urls = context.tool_args.get("urls")
    if isinstance(urls, list):
        return [str(url) for url in urls]
    command = context.action_text()
    if not command:
        return []
    return [token for token in command.split() if "://" in token or "." in token and "/" in token]


def _with_scheme(url: str) -> str:
    return url if "://" in url else f"https://{url}"


def _host_is_private(host: str) -> bool:
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            addresses = [ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, None)]
        except (OSError, ValueError):
            return False
    return any(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        for address in addresses
    )
