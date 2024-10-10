# KitsuNet
### Envío de tráfico sintético

prerequisitos:
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo apt install cargo libpcap-dev
```

Toolchain:
```
cargo build
sudo setcap cap_net_raw=eip target/debug/trafik
./target/debug/trafik --{client | 5gclient | server}
```
