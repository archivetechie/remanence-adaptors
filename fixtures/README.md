# Fixture provenance

The checked-in BRU dumps are synthetic test vectors. They contain no customer
data and were not produced by the adapter under test. Their block layout and
checksums were independently checked with the original vendor's Linux BRU 17.0
reader:

- archived vendor package:
  `Server_Linux-i686-glibc2.3_1.2.0.tgz` from the original
  `www.tolisgroup.com/downloads/bruserver/Servers/` distribution;
- Internet Archive capture
  [`20060315184642`](https://web.archive.org/web/20060315184642id_/http://www.tolisgroup.com/downloads/bruserver/Servers/Server_Linux-i686-glibc2.3_1.2.0.tgz);
- package SHA-256:
  `c388fe524d16c1d1abba007f003358755c64dd249797a53112a7b55adea50d7c`;
- `bru` executable SHA-256:
  `26ffa2bf6191384697cbb97bdfe927e5127921e211a84e181ae818a1ecf30124`.

The reference executable is proprietary and is not redistributed here. Its
expired demonstration license still permits inspect, list, and restore modes,
which are the only modes used for validation.

`minimal.bru.b64` decodes to an 8 KiB dump with SHA-256
`271e1d624042dbd50b4b3572173cb9e1d6b4f0d94fff8fd1f107d5ce68d2f070`.
The vendor reader's inspect mode reports one regular file and no checksum,
sequence, or synchronization warning; restore mode produces
`camera/a.txt` containing `abc`.

`reference-edge.bru` is a 12 KiB dump with SHA-256
`1802618a098ca6894f06efa2f7b944bfa5701a0ac07f334b0359eb3f5ccc903d`.
The vendor reader's inspect mode reports the UTF-8 directory `café` and a
121-byte regular-file path, reads six logical blocks, and emits no checksum,
sequence, or synchronization warning. The regular file spans two continuation
blocks.

The corresponding reference commands were:

```sh
bru -ivvvB -b 2k -f <fixture>
bru -x -ur -B -b 2k -f <fixture>
```

These fixtures establish compatibility with an independent reader, but they do
not stand in for migration acceptance tests on the source tapes. Physical read
damage is exercised with fault-injecting tape sources in the Rust tests because
that transport condition cannot be represented in a byte-stream dump.
Software-compression markers are also generated in the Rust tests to assert
that unsupported members fail before catalog or payload emission.
