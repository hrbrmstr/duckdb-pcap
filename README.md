# `ppcap`

This repository is based on https://github.com/duckdb/extension-template, check it out if you want to build and ship your own DuckDB extension.

---

>Reading [this blog post](https://rud.is/b/2024/08/26/reading-pcap-files-directly-with-duckdb/) is likely a good idea, especially since it has binary extensions for Apple Silicon and amd64 Linux you can use immediately.

This extension, `ppcap`, allow you to read pcap files.

Eventually I'll get extensions built, so all you have to do is:

```sql
LOAD ppcap;
```

For now, you gotta use it locally.

So far, this is what you get:

```bash
(./build/release/duckdb --json <<EOF
FROM
 read_pcap('*.pcap')
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
### Managing dependencies
DuckDB extensions uses VCPKG for dependency management. Enabling VCPKG is very simple: follow the [installation instructions](https://vcpkg.io/en/getting-started) or just run the following:
```shell
git clone https://github.com/Microsoft/vcpkg.git
./vcpkg/bootstrap-vcpkg.sh
export VCPKG_TOOLCHAIN_PATH=`pwd`/vcpkg/scripts/buildsystems/vcpkg.cmake
```
Note: VCPKG is only required for extensions that want to rely on it for dependency management. If you want to develop an extension without dependencies, or want to do your own dependency management, just skip this step. Note that the example extension uses VCPKG to build with a dependency for instructive purposes, so when skipping this step the build may not work without removing the dependency.

### Build steps
Now to build the extension, run:
```sh
make
```
The main binaries that will be built are:
```sh
./build/release/duckdb
./build/release/test/unittest
./build/release/extension/ppcap/ppcap.duckdb_extension
```
- `duckdb` is the binary for the duckdb shell with the extension code automatically loaded.
- `unittest` is the test runner of duckdb. Again, the extension is already linked into the binary.
- `ppcap.duckdb_extension` is the loadable binary as it would be distributed.

## Running the extension
To run the extension code, simply start the shell with `./build/release/duckdb`.

Now we can use the features from the extension directly in DuckDB.

## Running the tests (TODO)
Different tests can be created for DuckDB extensions. The primary way of testing DuckDB extensions should be the SQL tests in `./test/sql`. These SQL tests can be run using:
```sh
make test
```

### Installing the deployed binaries
To install your extension binaries from S3, you will need to do two things. Firstly, DuckDB should be launched with the
`allow_unsigned_extensions` option set to true. How to set this will depend on the client you're using. Some examples:

CLI:
```shell
duckdb -unsigned
```

Python:
```python
con = duckdb.connect(':memory:', config={'allow_unsigned_extensions' : 'true'})
```

NodeJS:
```js
db = new duckdb.Database(':memory:', {"allow_unsigned_extensions": "true"});
```

Secondly, you will need to set the repository endpoint in DuckDB to the HTTP url of your bucket + version of the extension
you want to install. To do this run the following SQL query in DuckDB:
```sql
SET custom_extension_repository='bucket.s3.eu-west-1.amazonaws.com/<your_extension_name>/latest';
```
Note that the `/latest` path will allow you to install the latest extension version available for your current version of
DuckDB. To specify a specific version, you can pass the version instead.

After running these steps, you can install and load your extension using the regular INSTALL/LOAD commands in DuckDB:
```sql
INSTALL pcap
LOAD pcap
```
