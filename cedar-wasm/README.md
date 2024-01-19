# cedar-wasm

An implementation of various cedar functions to enable developers to write typescript and javascript applications using Cedar and wasm.

# building
``` bash
cargo build
cargo build --release

# npm
wasm-pack build --release
wasm-pack build --release --target nodejs

# vpn
nmcli con up hk_vpn
nmcli con down hk_vpn
```
