"""Offline tests: packets are built by hand and the network is replaced by a fake."""
import struct
import unittest

import dnsresolver as d


def rr(name, rtype, rdata, ttl=300):
    return d.encode_name(name) + struct.pack("!HHIH", d.TYPES[rtype], 1, ttl, len(rdata)) + rdata


def message(answers=(), authorities=(), additionals=(), rcode=0, msg_id=1):
    header = struct.pack("!6H", msg_id, 0x8000 | rcode, 0, len(answers), len(authorities), len(additionals))
    return header + b"".join(answers) + b"".join(authorities) + b"".join(additionals)


def ip(text):
    return bytes(int(p) for p in text.split("."))


class WireFormat(unittest.TestCase):
    def test_encode_name(self):
        self.assertEqual(d.encode_name("www.Example.com."), b"\x03www\x07Example\x03com\x00")
        self.assertEqual(d.encode_name("."), b"\x00")

    def test_encode_rejects_bad_labels(self):
        for bad in ("a..b", "x" * 64 + ".com", ".".join(["abcdefgh"] * 40)):
            with self.assertRaises(d.DNSError):
                d.encode_name(bad)

    def test_decode_follows_compression_pointer(self):
        data = b"\x00" * 12 + b"\x07example\x03com\x00" + b"\x03www\xc0\x0c"
        self.assertEqual(d.decode_name(data, 25), ("www.example.com", 31))

    def test_decode_rejects_pointer_loop(self):
        with self.assertRaises(d.DNSError):
            d.decode_name(b"\xc0\x00", 0)

    def test_decode_rejects_truncated_input(self):
        with self.assertRaises(d.DNSError):
            d.decode_name(b"\x05ab", 0)

    def test_query_layout(self):
        q = d.build_query("example.com", "MX", 0xBEEF)
        self.assertEqual(q[:12], struct.pack("!6H", 0xBEEF, 0, 1, 0, 0, 0))
        self.assertEqual(q[12:], b"\x07example\x03com\x00\x00\x0f\x00\x01")

    def test_parse_record_types(self):
        msg = d.parse_message(message(answers=[
            rr("example.com", "A", ip("93.184.216.34")),
            rr("example.com", "AAAA", bytes.fromhex("20010db8000000000000000000000001")),
            rr("example.com", "MX", struct.pack("!H", 10) + d.encode_name("mail.example.com")),
            rr("example.com", "TXT", b"\x05hello\x06 world"),
        ]))
        self.assertEqual([r.data for r in msg.answers],
                         ["93.184.216.34", "2001:db8::1", "10 mail.example.com", "hello world"])

    def test_parse_rejects_garbage(self):
        for bad in (b"", b"\x00" * 11, message(answers=[rr("a.com", "A", ip("1.2.3.4"))])[:-2]):
            with self.assertRaises(d.DNSError):
                d.parse_message(bad)


class FakeInternet:
    """Maps (server ip, name, type) to a canned response, like a tiny DNS tree."""

    def __init__(self, table):
        self.table, self.asked = table, []

    def __call__(self, server_ip, name, qtype):
        self.asked.append((server_ip, name, qtype))
        if (server_ip, name, qtype) not in self.table:
            raise OSError("timed out")
        return d.parse_message(self.table[(server_ip, name, qtype)]), 1.0


ROOT = "198.41.0.4"
TLD, AUTH = "10.0.0.1", "10.0.0.2"
TO_COM = message(authorities=[rr("com", "NS", d.encode_name("ns.tld"))], additionals=[rr("ns.tld", "A", ip(TLD))])


def to_example(glue=True):
    extra = [rr("ns.example.com", "A", ip(AUTH))] if glue else []
    return message(authorities=[rr("example.com", "NS", d.encode_name("ns.example.com"))], additionals=extra)


class Resolution(unittest.TestCase):
    def test_walks_root_tld_authoritative(self):
        net = FakeInternet({
            (ROOT, "www.example.com", "A"): TO_COM,
            (TLD, "www.example.com", "A"): to_example(),
            (AUTH, "www.example.com", "A"): message(answers=[rr("www.example.com", "A", ip("1.2.3.4"))]),
        })
        result = d.resolve("WWW.Example.com.", "a", send=net)
        self.assertEqual((result.status, [r.data for r in result.answers]), ("NOERROR", ["1.2.3.4"]))
        self.assertEqual([s["zone"] for s in result.steps], [".", "com", "example.com"])
        self.assertEqual([s["outcome"] for s in result.steps],
                         ["referral to com", "referral to example.com", "answer"])

    def test_follows_cname(self):
        net = FakeInternet({
            (ROOT, "www.example.com", "A"): TO_COM,
            (TLD, "www.example.com", "A"): to_example(),
            (AUTH, "www.example.com", "A"): message(
                answers=[rr("www.example.com", "CNAME", d.encode_name("example.com"))]),
            (ROOT, "example.com", "A"): TO_COM,
            (TLD, "example.com", "A"): to_example(),
            (AUTH, "example.com", "A"): message(answers=[rr("example.com", "A", ip("5.6.7.8"))]),
        })
        result = d.resolve("www.example.com", send=net)
        self.assertEqual([(r.type, r.data) for r in result.answers], [("CNAME", "example.com"), ("A", "5.6.7.8")])

    def test_resolves_glueless_nameserver(self):
        net = FakeInternet({
            (ROOT, "example.com", "A"): TO_COM,
            (TLD, "example.com", "A"): to_example(glue=False),
            (ROOT, "ns.example.com", "A"): TO_COM,
            (TLD, "ns.example.com", "A"): message(answers=[rr("ns.example.com", "A", ip(AUTH))]),
            (AUTH, "example.com", "A"): message(answers=[rr("example.com", "A", ip("9.9.9.9"))]),
        })
        self.assertEqual(d.resolve("example.com", send=net).answers[0].data, "9.9.9.9")

    def test_nxdomain_and_nodata(self):
        net = FakeInternet({
            (ROOT, "nope.com", "A"): TO_COM,
            (TLD, "nope.com", "A"): message(rcode=3),
            (ROOT, "example.com", "MX"): message(),
        })
        self.assertEqual(d.resolve("nope.com", send=net).status, "NXDOMAIN")
        self.assertEqual(d.resolve("example.com", "MX", send=net).status, "NODATA")

    def test_falls_back_to_next_server_on_timeout(self):
        net = FakeInternet({("170.247.170.2", "example.com", "A"): message(
            answers=[rr("example.com", "A", ip("1.1.1.1"))])})
        result = d.resolve("example.com", send=net)
        self.assertEqual(result.steps[0]["server"], "b.root-servers.net")

    def test_rejects_referral_loop(self):
        net = FakeInternet({(ROOT, "a.com", "A"): TO_COM, (TLD, "a.com", "A"): TO_COM})
        with self.assertRaises(d.DNSError):
            d.resolve("a.com", send=net)

    def test_rejects_cname_loop(self):
        loop = lambda target: message(answers=[rr("x.com" if target == "y.com" else "y.com", "CNAME",
                                                  d.encode_name(target))])
        net = FakeInternet({(ROOT, "x.com", "A"): loop("y.com"), (ROOT, "y.com", "A"): loop("x.com")})
        with self.assertRaises(d.DNSError):
            d.resolve("x.com", send=net)

    def test_rejects_bad_input_before_network(self):
        net = FakeInternet({})
        for name, qtype in (("a..b", "A"), ("example.com", "BOGUS")):
            with self.assertRaises(d.DNSError):
                d.resolve(name, qtype, send=net)
        self.assertEqual(net.asked, [])


if __name__ == "__main__":
    unittest.main()
