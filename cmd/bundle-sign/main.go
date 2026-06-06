// Command bundle-sign signs AccessGate WASM policy bundles with an Ed25519 private key,
// producing a detached signature file that the proxy verifies at load time.
//
// Signature convention: for a bundle at "<bundle>.wasm", the detached signature is written
// to "<bundle>.wasm.sig" as base64-encoded Ed25519 signature bytes computed over the exact
// raw bundle bytes. The proxy verifies this signature (fail-closed) when
// bundle_public_key_path is configured. See docs/GUIDE-POLICY-SIGNING.md.
//
// Usage:
//
//	# Generate a new Ed25519 keypair (PEM, PKIX public / PKCS#8 private):
//	bundle-sign -genkey -priv policy_key.pem -pub policy_key.pub.pem
//
//	# Sign a bundle (writes policy.wasm.sig):
//	bundle-sign -priv policy_key.pem -bundle policy.wasm
//
//	# Sign to an explicit output path:
//	bundle-sign -priv policy_key.pem -bundle policy.wasm -out custom.sig
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if err := run(os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "bundle-sign: %v\n", err)
		os.Exit(1)
	}
}

// run parses args and dispatches. It is separated from main for testability.
func run(args []string, logw *os.File) error {
	fs := flag.NewFlagSet("bundle-sign", flag.ContinueOnError)
	fs.SetOutput(logw)
	var (
		genkey  = fs.Bool("genkey", false, "generate a new Ed25519 keypair (PEM) and exit")
		privPEM = fs.String("priv", "", "path to the Ed25519 private key (PEM, PKCS#8). For -genkey, the output path.")
		pubPEM  = fs.String("pub", "", "for -genkey, the public key output path (PEM, PKIX)")
		bundle  = fs.String("bundle", "", "path to the .wasm bundle to sign")
		out     = fs.String("out", "", "signature output path (default: <bundle>.sig)")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *genkey {
		if *privPEM == "" || *pubPEM == "" {
			return fmt.Errorf("-genkey requires -priv <out> and -pub <out>")
		}
		if err := generateKeypair(*privPEM, *pubPEM); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(logw, "wrote private key %s and public key %s\n", *privPEM, *pubPEM)
		return nil
	}

	if *privPEM == "" || *bundle == "" {
		return fmt.Errorf("signing requires -priv <key.pem> and -bundle <path.wasm> (or use -genkey)")
	}
	sigPath := *out
	if sigPath == "" {
		sigPath = defaultSignaturePath(*bundle)
	}
	if err := signBundle(*privPEM, *bundle, sigPath); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(logw, "wrote signature %s\n", sigPath)
	return nil
}
