# Prometheus TP-Link P110 exporter in Rust
## Build
Simply build using Cargo, as only dependency is openssl
## Running
Set `username`, `password`, and any amount of host(s) (plugs) you want to monitor. Use the included `dashboard.json` once prometheus is scraping the exporter.
```bash
$> prometheus-tplink-p110-exporter --help
prometheus-tplink-p110-exporter 0.1.0
Ian Johannesen <ij@perlpimp.net>

USAGE:
    prometheus-tplink-p110-exporter [OPTIONS] --username <USERNAME> --password <PASSWORD>

OPTIONS:
    -h, --help                               Print help information
        --host <HOST>
        --listen-address <LISTEN_ADDRESS>    [default: 127.0.0.1]
        --listen-port <LISTEN_PORT>          [default: 9984]
        --password <PASSWORD>
        --username <USERNAME>
    -V, --version                            Print version information

$> prometheus-tplink-p110-exporter \
    --username some@email \
    --password somepassword \
    --host 192.168.1.1
```
