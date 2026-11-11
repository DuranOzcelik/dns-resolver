"""Iterative DNS resolver written from scratch (RFC 1035). Standard library only.

It never asks a recursive resolver such as 8.8.8.8. It starts at a root server
and follows referrals down to the authoritative server, recording every hop.

    python dnsresolver.py example.com [A|AAAA|NS|CNAME|MX|TXT|SOA]
"""
import ipaddress
import secrets
import socket
import struct
import sys
import time
from dataclasses import dataclass, field

ROOT_SERVERS = {
    "a.root-servers.net": "198.41.0.4",
    "b.root-servers.net": "170.247.170.2",
    "c.root-servers.net": "192.33.4.12",
    "d.root-servers.net": "199.7.91.13",
}
TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}
TYPE_NAMES = {v: k for k, v in TYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
MAX_HOPS = 16   # referrals followed for one name
MAX_DEPTH = 8   # nested lookups (CNAME chains, glueless nameservers)


class DNSError(Exception):
    pass


@dataclass
class Record:
    name: str
    type: str
    ttl: int
    data: str


@dataclass
class Message:
    id: int
    rcode: int
    truncated: bool
    authoritative: bool
    answers: list
    authorities: list
    additionals: list


@dataclass
class Result:
    status: str
    answers: list
    steps: list = field(default_factory=list)


def normalize(name):
    return name.strip().rstrip(".").lower() or "."


def encode_name(name):
    """'www.example.com' -> b'\\x03www\\x07example\\x03com\\x00'"""
    out = bytearray()
    name = name.strip().rstrip(".")
    for label in name.split(".") if name else []:
        try:
            raw = label.encode("idna")
        except UnicodeError as exc:
            raise DNSError(f"invalid label {label!r}") from exc
        if not 1 <= len(raw) <= 63:
            raise DNSError(f"label must be 1-63 bytes: {label!r}")
        out.append(len(raw))
        out += raw
    out.append(0)
    if len(out) > 255:
        raise DNSError("name longer than 255 bytes")
    return bytes(out)


def decode_name(data, offset):
    """Read a possibly compressed name. Returns (name, offset just past it)."""
    labels, end, jumps = [], None, 0
    while True:
        if offset >= len(data):
            raise DNSError("truncated name")
        length = data[offset]
        if length & 0xC0 == 0xC0:  # compression pointer (RFC 1035 4.1.4)
            if offset + 1 >= len(data):
                raise DNSError("truncated pointer")
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            jumps += 1
            if jumps > 64:  # a malicious packet can point at itself forever
                raise DNSError("compression loop")
            continue
        if length & 0xC0:
            raise DNSError("unsupported label type")
        offset += 1
        if length == 0:
            break
        if offset + length > len(data):
            raise DNSError("truncated label")
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels).lower() or ".", offset if end is None else end


def build_query(name, qtype, query_id):
    # flags = 0: recursion NOT desired, we do the walking ourselves
    header = struct.pack("!6H", query_id, 0, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack("!2H", TYPES[qtype], 1)


def _rdata(data, offset, length, rtype):
    raw = data[offset:offset + length]
    if (rtype == 1 and length == 4) or (rtype == 28 and length == 16):
        return str(ipaddress.ip_address(raw))
    if rtype in (2, 5):
        return decode_name(data, offset)[0]
    if rtype == 15 and length >= 3:
        return f"{struct.unpack('!H', raw[:2])[0]} {decode_name(data, offset + 2)[0]}"
    if rtype == 16:
        parts, i = [], 0
        while i < length:
            size = raw[i]
            parts.append(raw[i + 1:i + 1 + size].decode("utf-8", "replace"))
            i += 1 + size
        return "".join(parts)
    if rtype == 6:
        mname, pos = decode_name(data, offset)
        rname, pos = decode_name(data, pos)
        if pos + 4 > len(data):
            raise DNSError("truncated SOA")
        return f"{mname} {rname} {struct.unpack('!I', data[pos:pos + 4])[0]}"
    return raw.hex()


def parse_message(data):
    if len(data) < 12:
        raise DNSError("message shorter than header")
    msg_id, flags, qd, an, ns, ar = struct.unpack("!6H", data[:12])
    offset = 12
    for _ in range(qd):
        _, offset = decode_name(data, offset)
        offset += 4
    sections = []
    for count in (an, ns, ar):
        records = []
        for _ in range(count):
            name, offset = decode_name(data, offset)
            if offset + 10 > len(data):
                raise DNSError("truncated record")
            rtype, _rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
            offset += 10
            if offset + rdlen > len(data):
                raise DNSError("truncated rdata")
            records.append(Record(name, TYPE_NAMES.get(rtype, f"TYPE{rtype}"), ttl,
                                  _rdata(data, offset, rdlen, rtype)))
            offset += rdlen
        sections.append(records)
    return Message(msg_id, flags & 0xF, bool(flags & 0x0200), bool(flags & 0x0400), *sections)


def _recv_exact(sock, size):
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise DNSError("TCP connection closed early")
        buf += chunk
    return buf


def query(server_ip, name, qtype, timeout=3.0):
    """Send one question to one server. Returns (Message, elapsed milliseconds)."""
    query_id = secrets.randbits(16)
    packet = build_query(name, qtype, query_id)
    start = time.perf_counter()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect((server_ip, 53))  # connect() makes the OS drop replies from other hosts
        sock.send(packet)
        msg = parse_message(sock.recv(4096))
    if msg.truncated:  # answer did not fit in a UDP datagram: retry over TCP
        with socket.create_connection((server_ip, 53), timeout=timeout) as sock:
            sock.sendall(struct.pack("!H", len(packet)) + packet)
            size = struct.unpack("!H", _recv_exact(sock, 2))[0]
            msg = parse_message(_recv_exact(sock, size))
    if msg.id != query_id:
        raise DNSError("response ID does not match query")
    return msg, (time.perf_counter() - start) * 1000


def _ask_any(servers, name, qtype, send):
    last = None
    for server in servers[:4]:
        try:
            msg, ms = send(server[1], name, qtype)
            return msg, server, ms
        except (OSError, DNSError) as exc:
            last = exc
    raise DNSError(f"no nameserver answered for {name}: {last}")


def _depth(zone):
    return 0 if zone == "." else zone.count(".") + 1


def resolve(name, qtype="A", send=query, steps=None, depth=0):
    """Walk from the root servers to the answer. `steps` collects every hop."""
    qtype = qtype.upper()
    if qtype not in TYPES:
        raise DNSError(f"unsupported record type {qtype!r}")
    name = normalize(name)
    encode_name(name)  # validate before touching the network
    steps = [] if steps is None else steps
    if depth > MAX_DEPTH:
        raise DNSError("too many nested lookups (CNAME or nameserver loop?)")

    servers, zone = list(ROOT_SERVERS.items()), "."
    for _ in range(MAX_HOPS):
        msg, server, ms = _ask_any(servers, name, qtype, send)
        step = {"server": server[0], "ip": server[1], "zone": zone, "depth": depth,
                "question": f"{name} {qtype}", "ms": round(ms, 1)}
        steps.append(step)

        if msg.rcode != 0:
            step["outcome"] = RCODES.get(msg.rcode, f"RCODE{msg.rcode}")
            return Result(step["outcome"], [], steps)

        answers = [r for r in msg.answers if r.name == name and r.type == qtype]
        if answers:
            step["outcome"] = "answer"
            return Result("NOERROR", answers, steps)

        cname = next((r for r in msg.answers if r.name == name and r.type == "CNAME"), None)
        if cname:
            step["outcome"] = f"alias of {cname.data}"
            rest = resolve(cname.data, qtype, send, steps, depth + 1)
            return Result(rest.status, [cname] + rest.answers, steps)

        referral = [r for r in msg.authorities if r.type == "NS"]
        if not referral:
            step["outcome"] = "no data"
            return Result("NODATA", [], steps)

        new_zone = referral[0].name
        in_zone = new_zone == "." or name == new_zone or name.endswith("." + new_zone)
        if not in_zone or _depth(new_zone) <= _depth(zone):
            # a referral must move closer to the name, otherwise we would loop
            raise DNSError(f"lame referral from {server[0]} to {new_zone}")
        step["outcome"] = f"referral to {new_zone}"

        # shortcut: glue is trusted as-is; safe here because nothing is cached
        # between lookups. Add bailiwick checks before adding a cache.
        glue = {r.name: r.data for r in msg.additionals if r.type == "A"}
        servers = [(r.data, glue[r.data]) for r in referral if r.data in glue]
        for ns in referral if not servers else []:
            try:  # glueless delegation: resolve the nameserver's own address first
                found = resolve(ns.data, "A", send, steps, depth + 1)
            except DNSError:
                continue
            ips = [a.data for a in found.answers if a.type == "A"]
            if ips:
                servers = [(ns.data, ips[0])]
                break
        if not servers:
            raise DNSError(f"could not find an address for any {new_zone} nameserver")
        zone = new_zone
    raise DNSError("too many referrals")


def main(argv):
    if not 2 <= len(argv) <= 3:
        print(__doc__.strip().splitlines()[-1].strip(), file=sys.stderr)
        return 2
    try:
        result = resolve(argv[1], argv[2] if len(argv) == 3 else "A")
    except DNSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for i, s in enumerate(result.steps, 1):
        print(f"{i:>2}. {'  ' * s['depth']}{s['question']:<32} @ {s['server']} ({s['ip']}) "
              f"[{s['zone']}]  {s['ms']} ms  -> {s['outcome']}")
    print(f"\n{result.status}")
    for r in result.answers:
        print(f"{r.name}\t{r.ttl}\t{r.type}\t{r.data}")
    return 0 if result.status == "NOERROR" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
