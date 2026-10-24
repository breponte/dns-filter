#!/usr/bin/env python3
"""
DNS filtering proxy: blocks YouTube domains, forwards everything else upstream.

Setup:   pip install dnslib
Test:    sudo python3 dns_filter.py            # binds :53 (needs root)
         python3 dns_filter.py --port 5353     # no root needed
         Resolve-DnsName youtube.com -Server 127.0.0.1    # blocked
         Resolve-DnsName example.com -Server 127.0.0.1    # resolves normally
"""
import argparse
import socket

from dnslib import AAAA, A, DNSRecord, QTYPE, RCODE, RR
from dnslib.server import BaseResolver, DNSLogger, DNSServer

BLOCKED_DOMAINS = {
    "youtube.com",
    "youtu.be",
    "youtube-nocookie.com",
    "youtubei.googleapis.com",
    "youtube.googleapis.com",
    "ytimg.com",
    "googlevideo.com",
    "yt3.ggpht.com",
}


class FilterResolver(BaseResolver):
    def __init__(self, upstream: str, upstream_port: int, mode: str):
        self.upstream = upstream    # IP address of the upstream DNS resolver
        self.upstream_port = upstream_port  # Port of the upstream DNS resolver
        self.mode = mode  # "nxdomain" or "sinkhole"
            # "nxdomain": return NXDOMAIN for blocked domains
            # "sinkhole": return spoofed answer

    @staticmethod
    def is_blocked(qname) -> bool:
        name = str(qname).rstrip(".").lower()
        # Match the domain itself and any subdomain (www.youtube.com, m.youtube.com, ...)
        return any(name == d or name.endswith("." + d) for d in BLOCKED_DOMAINS)

    def resolve(self, request, handler):
        qname = request.q.qname

        if self.is_blocked(qname):
            reply = request.reply()
            if self.mode == "nxdomain":
                reply.header.rcode = RCODE.NXDOMAIN
            elif request.q.qtype == QTYPE.A:
                reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=60))
            elif request.q.qtype == QTYPE.AAAA:
                reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA("::"), ttl=60))
            return reply

        # Not blocked: forward to the upstream resolver
        try:
            raw = request.send(self.upstream, self.upstream_port, timeout=3)
            return DNSRecord.parse(raw)
        except (socket.timeout, OSError):
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            return reply


def main():
    p = argparse.ArgumentParser(description="DNS filter for YouTube domains")
    p.add_argument("--listen", default="127.0.0.1")
    p.add_argument("--port", type=int, default=53)
    p.add_argument("--upstream", default="1.1.1.1")
    p.add_argument("--upstream-port", type=int, default=53)
    p.add_argument("--mode", choices=["nxdomain", "sinkhole"], default="nxdomain")
    args = p.parse_args()

    resolver = FilterResolver(args.upstream, args.upstream_port, args.mode)
    server = DNSServer(
        resolver,
        port=args.port,
        address=args.listen,
        logger=DNSLogger("request,error", prefix=False),
    )
    print(f"Listening on {args.listen}:{args.port}, upstream {args.upstream}, mode={args.mode}")
    server.start()  # blocks until Ctrl+C


if __name__ == "__main__":
    main()