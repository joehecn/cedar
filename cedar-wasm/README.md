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

# example
``` js
import { getCedarVersion, isAuthorized } from "cedar-wasm";

// getCedarVersion
const version = getCedarVersion();
console.log({ version });

// isAuthorized
const principal = 'User::"alice"';
const action = 'Action::"read"';
const resource = 'Photo::"foo.jpg"';
const context = "{}";
const policies = `
    permit(
      principal == User::"alice",
      action    in [Action::"read", Action::"edit"],
      resource  == Photo::"foo.jpg"
    );
  `;
const entities = "[]";
const result = isAuthorized(
  principal,
  action,
  resource,
  context,
  policies,
  entities
);
console.log(JSON.parse(result));
```
