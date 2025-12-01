"""Simple DNS filter server using dnspython.

Behavior:
- Listens on UDP port (default 5353) and inspects incoming queries.
- If a queried name matches filter rules, returns an A record for 0.0.0.0.
- Otherwise forwards the query to an upstream resolver (default 8.8.8.8) and replies.
"""
from __future__ import annotations

import socket
import threading
from dataclasses import dataclass
from typing import Tuple

import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.rrset

from .filter_rules import FilterRules


@dataclass
class ServerConfig:
    listen_addr: str = "0.0.0.0"
    listen_port: int = 5353
    upstream: Tuple[str, int] = ("8.8.8.8", 53)
    block_address: str = "0.0.0.0"
    ttl: int = 60


class DNSServer:
    def __init__(self, rules: FilterRules, config: ServerConfig | None = None):
        self.rules = rules
        self.config = config or ServerConfig()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._running = False

    def start(self):
        self._sock.bind((self.config.listen_addr, self.config.listen_port))
        self._running = True
        threading.Thread(target=self._serve_loop, daemon=True).start()
        print(f"DNS filter listening on {self.config.listen_addr}:{self.config.listen_port}")

    def stop(self):
        self._running = False
        self._sock.close()

    def _serve_loop(self):
        while self._running:
            try:
                data, addr = self._sock.recvfrom(4096)
            except OSError:
                break
            threading.Thread(target=self._handle, args=(data, addr), daemon=True).start()

    def _handle(self, data: bytes, addr: Tuple[str, int]):
        try:
            req = dns.message.from_wire(data)
        except Exception:
            return

        if len(req.question) == 0:
            return

        q = req.question[0]
        qname = q.name.to_text()  # includes trailing dot

        if self.rules.is_blocked(qname):
            resp = self._make_block_response(req, qname, q.rdtype)
            self._sock.sendto(resp.to_wire(), addr)
            return

        # forward to upstream
        try:
            upstream_ip, upstream_port = self.config.upstream
            reply = dns.query.udp(req, upstream_ip, port=upstream_port, timeout=2)
            self._sock.sendto(reply.to_wire(), addr)
        except Exception:
            # on failure return SERVFAIL
            servfail = dns.message.make_response(req)
            servfail.set_rcode(dns.rcode.SERVFAIL)
            self._sock.sendto(servfail.to_wire(), addr)

    def _make_block_response(self, req: dns.message.Message, qname: str, rdtype: int) -> dns.message.Message:
        resp = dns.message.make_response(req)
        # only craft A responses for A queries; otherwise NXDOMAIN
        if rdtype == dns.rdatatype.A:
            rd = dns.rrset.from_text(qname, self.config.ttl, "IN", "A", self.config.block_address)
            resp.answer.append(rd)
            resp.set_rcode(dns.rcode.NOERROR)
        else:
            resp.set_rcode(dns.rcode.NXDOMAIN)
        return resp


def run_simple_server(rules_path: str, listen_port: int = 5353):
    rules = FilterRules(rules_path)
    srv = DNSServer(rules, ServerConfig(listen_port=listen_port))
    srv.start()
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        srv.stop()


if __name__ == "__main__":
    import sys

    rules_file = "/workspaces/dns-filter/config/blocked_domains.txt"
    port = 5353
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except Exception:
            pass
    run_simple_server(rules_file, listen_port=port)
