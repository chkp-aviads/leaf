<p align="center">
<img src=".github/assets/leaf-logo-horizontal-white-bg.png" alt="Leaf Logo" width="360">
</p>

<p align="center">
<img src="https://github.com/eycorsican/leaf/workflows/releases/badge.svg">
<img src="https://github.com/eycorsican/leaf/workflows/ci/badge.svg">
</p>

<h1 align="center">Leaf</h1>

<p align="center">
A versatile and efficient proxy framework.
</p>

## Supported Protocols

### Proxy Protocols

| Protocol | Inbound | Outbound |
|---|---|---|
| HTTP | ✅ | ❌ |
| SOCKS5 | ✅ | ✅ |
| Shadowsocks | ✅ | ✅ |
| Trojan | ✅ | ✅ |
| VMess | ❌ | ✅ |
| Vless | ❌ | ✅ |

### Transports & Security

| Transport | Inbound | Outbound | Notes |
|---|---|---|---|
| WebSocket | ✅ | ✅ | |
| TLS | ✅ | ✅ | |
| QUIC | ✅ | ✅ | |
| AMux | ✅ | ✅ | Leaf specific multiplexing |
| Obfs | ❌ | ✅ | Simple obfuscation |
| Reality | ❌ | ✅ | Xray Reality |
| MPTP | ✅ | ✅ | Multi-path Transport Protocol (Aggregation) ([Architecture](docs/mptp_architecture.md), [Usage](docs/mptp_usage.md)) |

### Traffic Control

| Feature | Inbound | Outbound | Notes |
|---|---|---|---|
| Chain | ✅ | ✅ | Proxy chaining |
| Failover | ❌ | ✅ | Failover with health check |

### Transparent Proxying

| Mechanism | Inbound | Outbound | Notes |
|---|---|---|---|
| TUN | ✅ | ❌ | Linux, macOS, Windows, iOS, Android; lwip, smoltcp |
| NF | ✅ | ❌ | Windows, [NetFilter SDK](https://netfiltersdk.com/) |
| TPROXY | ❌ | ❌ | Linux; Coming soon |

## Building

```sh
cargo build -p leaf-cli --release
./target/debug/leaf --help
```

## Picard WireGuard DNS

The `picard` feature exposes the `px_*` C API. Install the WireGuard config
with `px_wg_set_config` before starting the leaf instance. The `wireguard`
outbound attaches that instance's runtime at startup, without opening a tunnel.
The first proxied connection **or in-tunnel DNS lookup** brings the tunnel up.
DNS requests submitted before startup are queued until the runtime is attached.

For `px_wg_resolve`, a positive request id promises exactly one callback:
DNS records on success, or NULL on failure, cancellation, queued-request clear,
or runtime shutdown. A negative return never invokes the callback. The callback
can run before `px_wg_resolve` returns, and can run synchronously during
`px_wg_resolve_cancel` or `px_wg_clear`; callers must not hold locks that their
callback needs. Keep `user_data` valid until the callback runs, including after
cancellation, and copy the JSON string before returning from the callback.

The callback can also run on leaf's own thread while `px_shutdown` tears the
runtime down and drops unfinished lookups. That is inside a tokio context, so
the callback must not block, call `px_shutdown`, or call anything else that
blocks on a runtime.

Cancel requests if startup fails or a lookup times out; a cancelled request
never starts a tunnel. When disposing of an instance, also call `px_wg_clear`
to forget the config and release queued requests. The runtime is detached
when the instance exits or fails to start, and attaching a new instance's
runtime drops any tunnel built on the previous one, so a restart never leaves
a tunnel whose tasks died with the old runtime. `px_wg_stop`, sleep, and
memory trimming keep the config so a later lookup or connection can reconnect
on the existing runtime. Stopping or clearing a tunnel invalidates an
in-progress connection attempt; it cannot republish the old tunnel.

## License

This project is licensed under the [Apache License 2.0](https://github.com/eycorsican/leaf/blob/master/LICENSE).
