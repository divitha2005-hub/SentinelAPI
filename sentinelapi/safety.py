"""Target authorization guard. SentinelAPI sends hostile inputs, so it must only run
against systems the operator is allowed to test."""
from __future__ import annotations
import ipaddress, socket
from urllib.parse import urlparse


class UnauthorizedTarget(Exception):
    pass


def _is_local(host: str) -> bool:
    if host in ("localhost", "test"):          # "test" = in-process ASGI transport
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except OSError:
            return False
    return ip.is_loopback or ip.is_private


def check_target(base_url: str, authorized: bool = False, allow_hosts: list[str] | None = None) -> None:
    host = urlparse(base_url).hostname or ""
    if allow_hosts and host in allow_hosts:
        return
    if _is_local(host):
        return
    if not authorized:
        raise UnauthorizedTarget(
            f"'{host}' is not a local/private address. Fuzzing remote systems requires explicit "
            "permission: pass --authorized (you own the target or have written permission) "
            "or add the host to --allow-host.")
