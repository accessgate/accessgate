# Guide: Signing and Verifying WASM Policy Bundles

AccessGate's WASM policy engine loads compiled, language-agnostic policy bundles
(`.wasm`). Because a bundle is opaque executable code that makes every allow/deny
decision, its integrity and provenance are security-critical. AccessGate verifies a
detached **Ed25519 signature** for each bundle before it is compiled or instantiated, and
**fails closed** when verification cannot succeed.

This guide covers generating a keypair, signing a bundle, configuring the proxy to verify
it, and the exact fail-closed guarantee.

## Signature convention

- For a bundle at `policy.wasm`, the detached signature lives alongside it at
  `policy.wasm.sig`.
- The signature is an **Ed25519** signature over the **exact, raw bytes** of the bundle
  file.
- The `.sig` file content is the signature encoded as **standard base64** (a trailing
  newline is allowed). A raw 64-byte binary signature is also accepted.
- The public key is supplied to the proxy as a **PEM-encoded PKIX** key
  (`-----BEGIN PUBLIC KEY-----`, the form produced by `bundle-sign -genkey`). A bare
  base64 32-byte key is also accepted.

## 1. Generate a keypair

Use the `bundle-sign` CLI to generate an Ed25519 keypair. The private key is written as
PKCS#8 PEM with `0600` permissions; the public key as PKIX PEM.

```sh
go run ./cmd/bundle-sign -genkey \
  -priv policy_signing_key.pem \
  -pub  policy_signing_key.pub.pem
```

- Keep `policy_signing_key.pem` secret — anyone with it can sign bundles your proxy will
  trust. Store it in a secret manager / HSM, not in git.
- Distribute `policy_signing_key.pub.pem` to the environments running the proxy.

## 2. Sign a bundle

```sh
go run ./cmd/bundle-sign \
  -priv policy_signing_key.pem \
  -bundle policy.wasm
# wrote signature policy.wasm.sig
```

This writes `policy.wasm.sig` next to `policy.wasm`. To write the signature to an explicit
path, pass `-out`:

```sh
go run ./cmd/bundle-sign -priv policy_signing_key.pem -bundle policy.wasm -out dist/policy.wasm.sig
```

> Re-sign whenever the bundle changes. The signature covers the exact bytes; any edit to
> the `.wasm` invalidates the existing `.sig`.

## 3. Configure the proxy to verify

Point the proxy at the bundle and the public key:

```yaml
policy_engine: wasm
policy_bundle_path: /etc/accessgate/policy.wasm
bundle_public_key_path: /etc/accessgate/policy_signing_key.pub.pem
```

Deploy `policy.wasm` and `policy.wasm.sig` together. At startup (and whenever the bundle's
mtime changes) the proxy reads `policy.wasm`, locates `policy.wasm.sig`, and verifies the
signature against the configured public key **before** compiling or instantiating the
module.

## 4. The fail-closed guarantee

When `bundle_public_key_path` is set, the loader (`internal/policy/bundle.go`) refuses to
load a bundle unless its signature verifies. Specifically, the load **fails** (returns an
error and the unverified bundle is never compiled or instantiated) when:

- the `.sig` file is **missing**,
- the signature is **malformed** (wrong length / not base64),
- the public key is **unparseable** or not Ed25519, or
- the signature **does not validate** for the bundle bytes (tampered bundle, tampered
  signature, or signed by a different key).

There is **no fallback to loading the unverified bundle**. A signed deployment that fails
verification stops the proxy from coming up with that policy rather than silently serving an
untrusted one. Combined with the engine's fail-closed default
(`policy_fallback_allow` unset/false → deny with 503), an integrity failure denies traffic
rather than leaking it.

When `bundle_public_key_path` is **not** set, the proxy logs a warning and loads bundles
without integrity verification (unsigned mode). Set the public key in any environment where
bundle provenance matters — which is every production environment.

## Verifying a signature manually

The `.sig` is a standard base64 Ed25519 signature, so it can be checked with any Ed25519
tooling. The bytes signed are simply the raw contents of the `.wasm` file.
