# blackhole-oracle

The byte-identity oracle for the blackhole sink. It drives the pinned
xray-core's own `proxy/blackhole` handler over an in-memory pipe and prints
every octet the handler writes, so `crates/ferrox-core/src/blackhole.rs` can be
compared octet for octet.

`go.mod` replaces `github.com/xtls/xray-core` with `../../upstream/xray-core`,
so the checkout has to exist first:

```sh
./scripts/fetch-upstream.sh --only xray-core
```

`fetch-upstream.sh` accepts a checkout already at the pin even when its working
tree has local edits. Confirm it is clean before recording bytes:

```sh
git -C upstream/xray-core status --short
```

Then, from this directory:

```sh
go run . script.txt > expected.txt
```

`script.txt` is hand-written: one case per line, grammar in `main.go`. The
command regenerates only `expected.txt`, from the reference at the rev
`upstream/pins.toml` names. After a pin bump, run `go mod tidy` before
regenerating, then diff both files.
