# Ppcap

This repository is based on https://github.com/duckdb/extension-template, check it out if you want to build and ship your own DuckDB extension.

---

This extension, `ppcap`, allow you to read pcap files.

I need to figure out how to have it be just `pcap` but enough symbols collide with `libpcap` that it may take me a bit to figure that out.

So far, this is what you get:

```bash
(
./build/release/duckdb --json <<EOF
FROM
  read_pcap('*.pcap')
WHERE
  is_http(payload)
LIMIT 1
EOF
) | jq
[
  {
    "timestamp": "2024-07-23 16:31:06",
    "source_ip": "94.156.71.207",
    "dest_ip": "203.161.44.208",
    "source_port": 49678,
    "dest_port": 80,
    "length": 220,
    "tcp_session": "94.156.71.207:49678-203.161.44.208:80",
    "source_mac": "64:64:9b:4f:37:00",
    "dest_mac": "00:16:3c:cb:72:42",
    "protocols": "[Ethernet, IP, TCP]",
    "payload": "GET /_profiler/phpinfo HTTP/1.1\\x0D\\x0AHost: 203.161.44.208\\x0D\\x0AUser-Agent: Web Downloader/6.9\\x0D\\x0AAccept-Charset: utf-8\\x0D\\x0AAccept-Encoding: gzip\\x0D\\x0AConnection: close\\x0D\\x0A\\x0D\\x0A"
  }
]
```

There's a single function exposed:

- `it_http(payload)` will apply very naive heuristics on the payload and return `true` if it thinks the payload is an HTTP request or response. that will work on any `BLOB` field in DuckDB.

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

Now we can use the features from the extension directly in DuckDB. The template contains a single scalar function `ppcap()` that takes a string arguments and returns a string:
```
D select ppcap('Jane') as result;
┌───────────────┐
│    result     │
│    varchar    │
├───────────────┤
│ Ppcap Jane 🐥 │
└───────────────┘
```

## Running the tests
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
INSTALL ppcap
LOAD ppcap
```
