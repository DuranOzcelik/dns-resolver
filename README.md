# DNS Resolver from Scratch

An iterative DNS resolver written in pure Python. It builds and parses DNS packets by hand
(RFC 1035), starts at a root server and follows referrals down to the authoritative server,
the same walk a real recursive resolver performs. It never forwards the question to
`8.8.8.8` or to the operating system.

No dependencies. Only the Python standard library.

![Web UI resolving www.github.com hop by hop](docs/screenshot.png)

## What it does

- Encodes queries and decodes responses at the byte level, including name compression pointers
- Walks root → TLD → authoritative servers and records every hop with its latency
- Follows `CNAME` chains and resolves nameservers that come without glue records
- Falls back to TCP when a UDP response is truncated
- Supports `A`, `AAAA`, `NS`, `CNAME`, `MX`, `TXT` and `SOA`
- Ships with a command line tool and a small local web UI

## Usage

Requires Python 3.10 or newer.

```bash
python dnsresolver.py www.github.com
```

```
 1. www.github.com A   @ a.root-servers.net (198.41.0.4) [.]              254.9 ms  -> referral to com
 2. www.github.com A   @ l.gtld-servers.net (192.41.162.30) [com]          70.7 ms  -> referral to github.com
 3. www.github.com A   @ ns-421.awsdns-52.com (205.251.193.165) [github.com] 44.6 ms  -> alias of github.com
 4.   github.com A     @ a.root-servers.net (198.41.0.4) [.]              242.1 ms  -> referral to com
 5.   github.com A     @ l.gtld-servers.net (192.41.162.30) [com]          72.4 ms  -> referral to github.com
 6.   github.com A     @ ns-421.awsdns-52.com (205.251.193.165) [github.com] 32.5 ms  -> answer

NOERROR
www.github.com  3600  CNAME  github.com
github.com      60    A      140.82.121.3
```

Other record types:

```bash
python dnsresolver.py gmail.com MX
```

Web UI:

```bash
python web.py
```

Then open <http://127.0.0.1:8053>. The server listens on the loopback interface only.

## How it works

1. **Ask a root server.** The query is sent with the "recursion desired" flag off, so the
   server answers only what it knows. A root server does not know `www.github.com`, but it
   knows who runs `com` and replies with a *referral*: a list of nameservers plus their
   IP addresses (glue records).
2. **Follow the referral.** The same question goes to a `com` server, which refers to the
   `github.com` nameservers.
3. **Get the answer.** The authoritative server returns the record, or a `CNAME` that
   restarts the walk for the new name.

## Details that were not obvious

- **Compression pointers can loop.** A name in a DNS packet may point back to an earlier
  offset. A malformed packet can point at itself, so the parser limits the number of jumps.
- **Referrals must make progress.** A referral is accepted only if it points to a zone that
  is deeper than the current one and contains the name being resolved. Otherwise two
  misconfigured servers could bounce the resolver between them forever.
- **Glueless delegations.** Some referrals name a nameserver without giving its address. The
  resolver then pauses, resolves the nameserver's own name from the root, and continues.
- **Truncation.** When a response does not fit in a UDP datagram the server sets the `TC`
  bit, and the query is repeated over TCP with a two byte length prefix.
- **Replies are matched to queries.** Each query uses a random 16 bit ID and a connected UDP
  socket, so packets from other hosts or with the wrong ID are rejected.

## Tests

The tests run offline. Packets are assembled byte by byte and the network is replaced with a
fake DNS tree, so referral loops, CNAME loops, timeouts and malformed packets can be tested
deterministically.

```bash
python -m unittest -v
```

## Limitations

- No caching, so every lookup starts at the root. This keeps the trace complete but slow.
- No DNSSEC validation and no EDNS(0).
- Queries go to IPv4 nameservers only (`AAAA` records can still be looked up).

## License

MIT
