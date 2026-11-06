//! F3 xpub export (bridge-side demo).
//!
//! Derives an account-level extended public key through the narrow
//! `xpub_from_seed` edge (off-device, public output only): the seed is a
//! test-only local, borrowed and zeroized inside the call, and only the
//! Base58check `xpub` string ever comes back. No transport, no device, no
//! private bytes in the output; the on-device path additionally requires the
//! session UP latch and the binding -> UP transport gates.

use aegis_bridge::xpub_from_seed;

fn main() {
    // Test-only seed (official protocol vector seed, 16 bytes).
    let seed = "000102030405060708090a0b0c0d0e0f";
    for (network, account) in [("bitcoin", 0u32), ("ethereum", 0u32), ("bitcoin", 1u32)] {
        let xpub = xpub_from_seed(seed.to_string(), network.to_string(), account)
            .expect("test seed derives");
        assert!(xpub.starts_with("xpub"), "{network}/{account}");
        assert_eq!(xpub.len(), 111, "{network}/{account}");
        println!("{network} account {account}: {xpub}");
    }
    // Distinct accounts never share an xpub; networks without an
    // extended-key protocol fail closed.
    let first = xpub_from_seed(seed.to_string(), "bitcoin".to_string(), 0).unwrap();
    let second = xpub_from_seed(seed.to_string(), "bitcoin".to_string(), 1).unwrap();
    assert_ne!(first, second);
    assert!(xpub_from_seed(seed.to_string(), "solana".to_string(), 0).is_err());
    println!("xpub export ok (public-only output, seed never leaves the call)");
}
