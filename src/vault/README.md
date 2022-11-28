# Vaults

To support a wide variety of platforms `libwallet` has the concept of a vault,
an abstraction used to retreive the private keys used for signing.

## Backends

### Simple

An in memmory key storage that will forget keys at the end of a program's
execution. It's useful for tests and generating addresses.

### OS Keyring

A cross platform storage that uses the operating system's default keyring to
store the secret seed used to generate accounts. Useful for desktop wallets.

### Pass

A cross platform secret vault storage that uses pass-like implementation (using
GPG as backend) to encrypt the secret seed used to generate accounts. Requires
`gnupg` or `gpgme` as dependencies.

### Matrix

 [Secure Secret Storage and Sharing](https://matrix.org/docs/guides/implementing-more-advanced-e-2-ee-features-such-as-cross-signing#3-implementing-ssss) implementation of Matrix Protocol to share cross devices the seed needed to generate accounts. useful to keep your identity in a multi-device solution.




