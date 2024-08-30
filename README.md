# `ppcap`

This repository is based on https://github.com/duckdb/extension-template, check it out if you want to build and ship your own DuckDB extension.

---

This extension, `ppcap`, allow you to read pcap files.

>Reading [this blog post](https://rud.is/b/2024/08/26/reading-pcap-files-directly-with-duckdb/) is likely a good idea.

Binary versions of this extension are available for amd64 Linux (`linux_amd64` & `linux_amd64_gcc4`) and Apple Silicon. (`osx_arm64`).

```bash
$ duckdb -unsigned
v1.0.0 1f98600c2c
Enter ".help" for usage hints.
Connected to a transient in-memory database.
Use ".open FILENAME" to reopen on a persistent database.
D SET custom_extension_repository='https://w3c2.c20.e2-5.dev/ppcap/latest';
D INSTALL ppcap;
D LOAD ppcap;
```

---

For now, only reading local PCAP files is supported.

So far, this is what you get:

```bash
(./build/release/duckdb --json <<EOF
FROM
 read_pcap('scans.pcap')
SELECT
 *,
 extract_http_request_headers(payload) as req
WHERE is_http(payload)
LIMIT 2
EOF
) | jq
[
  {
    "timestamp": "2024-07-23 16:31:06",
    "source_ip": "94.156.71.207",
    "dest_ip": "203.161.44.208",
    "source_port": 49678,
    "dest_port": 80,
    "length": 154,
    "tcp_session": "94.156.71.207:49678-203.161.44.208:80",
    "source_mac": "64:64:9b:4f:37:00",
    "dest_mac": "00:16:3c:cb:72:42",
    "protocols": "[Ethernet, IP, TCP]",
    "payload": "GET /_profiler/phpinfo HTTP/1.1\\x0D\\x0AHost: 203.161.44.208\\x0D\\x0AUser-Agent: Web Downloader/6.9\\x0D\\x0AAccept-Charset: utf-8\\x0D\\x0AAccept-Encoding: gzip\\x0D\\x0AConnection: close\\x0D\\x0A\\x0D\\x0A",
    "tcp_flags": "[ACK, PSH]",
    "tcp_seq_num": "2072884123",
    "req": "[{'key': Host, 'value': 203.161.44.208}, {'key': User-Agent, 'value': Web Downloader/6.9}, {'key': Accept-Charset, 'value': utf-8}, {'key': Accept-Encoding, 'value': gzip}, {'key': Connection, 'value': close}]"
  },
  {
    "timestamp": "2024-07-23 16:31:06",
    "source_ip": "203.161.44.208",
    "dest_ip": "94.156.71.207",
    "source_port": 80,
    "dest_port": 49678,
    "length": 456,
    "tcp_session": "203.161.44.208:80-94.156.71.207:49678",
    "source_mac": "00:16:3c:cb:72:42",
    "dest_mac": "64:64:9b:4f:37:00",
    "protocols": "[Ethernet, IP, TCP]",
    "payload": "HTTP/1.1 404 Not Found\\x0D\\x0ADate: Tue, 23 Jul 2024 16:31:06 GMT\\x0D\\x0AServer: Apache/2.4.52 (Ubuntu)\\x0D\\x0AContent-Length: 276\\x0D\\x0AConnection: close\\x0D\\x0AContent-Type: text/html; charset=iso-8859-1\\x0D\\x0A\\x0D\\x0A<!DOCTYPE HTML PUBLIC \\x22-//IETF//DTD HTML 2.0//EN\\x22>\\x0A<html><head>\\x0A<title>404 Not Found</title>\\x0A</head><body>\\x0A<h1>Not Found</h1>\\x0A<p>The requested URL was not found on this server.</p>\\x0A<hr>\\x0A<address>Apache/2.4.52 (Ubuntu) Server at 203.161.44.208 Port 80</address>\\x0A</body></html>\\x0A",
    "tcp_flags": "[ACK, PSH]",
    "tcp_seq_num": "2821588265",
    "req": null
  }
]
```

There's a single function exposed:

- `is_http(payload)` will apply very naive heuristics on the payload and return `true` if it thinks the payload is an HTTP request or response. that will work on any `BLOB` field in DuckDB.
- `extract_http_request_headers(payload)` will do what it says on the tin provided ^^
- `extract_icmp_type`

Lots more to do!

And, you have to do the following to use it until I figure out the "make a standalone INSTALLable and LOADable extension.

I made this on macOS and I think you'll need to do some things to get this to work on Linux.

As usual I don't care abt Windows users. Make better life choices.

PRs welcome to get this working on the other operating systems. Not sure if this will ever be WASMable, but _I think_ it might be (ref: https://github.com/emscripten-core/emscripten/issues/16503).

`scans.pcap` is from https://www.malware-traffic-analysis.net/2024/08/08/index.html


## Building

```bash
$ git clone --recurse-submodules https://github.com/hrbrmstr/duckdb-ppcap.git
$ cd duckdb-ppcap
$ ./vcpkg/bootstrap-vcpkg.sh
$ just build # https://github.com/casey/just
# OR
$ VCPKG_TOOLCHAIN_PATH=`pwd`/vcpkg/scripts/buildsystems/vcpkg.cmake BUILD_PPCAP=1 make release
```
