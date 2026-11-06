//! F5 — wallet seed provisioning ceremony (RAM-only; no eFuse).
//!
//! BEHAVIOR: [`SeedCeremony`] owns one [`Mnemonic24`](crate::crypto::bip39::Mnemonic24)
//! (24 words, 256-bit entropy) for the wallet master seed. Every method that
//! touches secret material takes an explicit [`SeedSession`] (physical
//! presence and PIN-authentication latches owned by the caller, e.g. the
//! firmware button/UP latch and the PIN session); without the session the
//! call fails closed before any secret is touched. The raw seed is never
//! returned: consumers either seal it through the existing PIN-bound
//! [`AegisVault`](crate::vault::AegisVault) envelope
//! ([`SeedCeremony::export_sealed`]), derive a vault from it
//! ([`SeedCeremony::to_vault`]), or split it into a 2-of-3 Shamir backup
//! ([`SeedCeremony::split_backup`]). Persistence itself lives in firmware
//! (`wallet_seed_store`, sealed `SecureStorage` + snapshot/rollback +
//! verify-after-write); this module only produces/consumes the opaque sealed
//! bytes. No eFuse operation, no JSON, no new wire status: errors map to the
//! closed 9.5 set (`NeedUp` → `0x01`, `NeedPin` → `0x02`, everything else
//! fail-closed → `0x04`).
//!
//! Secret hygiene: [`Mnemonic24`] already redacts [`core::fmt::Debug`] and
//! zeroizes on drop; the ceremony wrapper repeats both so a debug dump of a
//! ceremony never leaks words, entropy, or fingerprints of intent beyond the
//! public [`SeedMetadata`].

use alloc::vec::Vec;
use rand_core::CryptoRng;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::shamir_slip39::{recover_secret_from_2_shares, split_secret_2_of_3, ShamirShare};
use crate::credential::{STATUS_BAD_ENVELOPE, STATUS_NEED_PIN, STATUS_NEED_UP};
use crate::crypto::bip39::Mnemonic24;
use crate::vault::AegisVault;

/// Authorized session for seed-ceremony calls (typed, no JSON).
///
/// The latches are owned by the caller (firmware UP latch + PIN session);
/// this struct only carries their already-verified outcome into the ceremony
/// so every secret touch is explicitly authorized at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeedSession {
    presence_confirmed: bool,
    pin_authenticated: bool,
}

impl SeedSession {
    /// Records the caller's already-verified latch outcomes.
    pub const fn authorize(presence_confirmed: bool, pin_authenticated: bool) -> Self {
        Self {
            presence_confirmed,
            pin_authenticated,
        }
    }

    /// Whether physical user presence was confirmed for this session.
    pub const fn presence_confirmed(&self) -> bool {
        self.presence_confirmed
    }

    /// Whether PIN authentication holds for this session.
    pub const fn pin_authenticated(&self) -> bool {
        self.pin_authenticated
    }

    fn require_up(&self) -> Result<(), SeedCeremonyError> {
        if self.presence_confirmed {
            Ok(())
        } else {
            Err(SeedCeremonyError::NeedUp)
        }
    }

    fn require_up_pin(&self) -> Result<(), SeedCeremonyError> {
        self.require_up()?;
        if self.pin_authenticated {
            Ok(())
        } else {
            Err(SeedCeremonyError::NeedPin)
        }
    }
}

/// Fail-closed ceremony errors, mapped to the closed 9.5 wire set.
///
/// `Storage` (seal/open or NVS round-trip failure) also maps to `0x04`:
/// no new wire status is introduced (backward-compat §9), the typed
/// distinction only exists inside the firmware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedCeremonyError {
    /// User presence required (9.5 `0x01`).
    NeedUp,
    /// PIN authentication required (9.5 `0x02`).
    NeedPin,
    /// Bad phrase/checksum, confirm mismatch, bad sealed envelope, wrong
    /// PIN token, or bad Shamir shares (9.5 `0x04`).
    BadEnvelope,
    /// Seal/open failure of the PIN-bound envelope (9.5 `0x04`).
    Storage,
}

impl SeedCeremonyError {
    /// Maps the error to its 9.5 wire status byte.
    pub fn status(self) -> u8 {
        match self {
            Self::NeedUp => STATUS_NEED_UP,
            Self::NeedPin => STATUS_NEED_PIN,
            Self::BadEnvelope | Self::Storage => STATUS_BAD_ENVELOPE,
        }
    }
}

impl core::fmt::Display for SeedCeremonyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NeedUp => write!(f, "seed ceremony requires user presence"),
            Self::NeedPin => write!(f, "seed ceremony requires PIN authentication"),
            Self::BadEnvelope => write!(f, "bad seed phrase, envelope, or backup shares"),
            Self::Storage => write!(f, "seed seal/open failure"),
        }
    }
}

/// Public, non-secret ceremony metadata (safe for `0x00` + metadata
/// responses, logs, and displays). Carries no private bytes: only the
/// word count, an 8-byte public fingerprint (`SHA-256(entropy)[..8]`, used
/// to confirm on both sides that reload restored the same seed), and
/// whether a Shamir backup was split in this ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeedMetadata {
    /// BIP-39 word count (always 24 for this ceremony).
    pub word_count: u8,
    /// Public fingerprint `SHA-256(entropy)[..8]`.
    pub fingerprint: [u8; 8],
    /// Whether [`SeedCeremony::split_backup`] ran in this ceremony.
    pub backed_up: bool,
}

/// Number of words every ceremony phrase holds.
pub const SEED_WORD_COUNT: u8 = 24;

/// Wallet seed provisioning ceremony: generate / import / confirm the
/// 24-word phrase, seal it for persistence, split 2-of-3 backups.
///
/// Holds the mnemonic in RAM only; zeroized on drop. Every secret-touching
/// method requires the matching [`SeedSession`] gates (reveal/confirm/
/// metadata need UP; import/seal/split/vault need UP+PIN, mirroring the
/// `WalletStore` import gate). Nothing here touches flash, eFuse, or the
/// wire: sealed bytes are opaque to the firmware persistence layer.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SeedCeremony {
    mnemonic: Mnemonic24,
    #[zeroize(skip)]
    backed_up: bool,
}

impl core::fmt::Debug for SeedCeremony {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SeedCeremony")
            .field("mnemonic", &"[REDACTED]")
            .field("backed_up", &self.backed_up)
            .finish()
    }
}

impl SeedCeremony {
    /// Starts a ceremony with a freshly generated phrase (gate UP).
    pub fn generate<R: CryptoRng>(
        session: &SeedSession,
        rng: &mut R,
    ) -> Result<Self, SeedCeremonyError> {
        session.require_up()?;
        let mnemonic = Mnemonic24::generate(rng).map_err(|_| SeedCeremonyError::BadEnvelope)?;
        Ok(Self {
            mnemonic,
            backed_up: false,
        })
    }

    /// Starts a ceremony by importing a 24-word phrase (gate UP+PIN,
    /// mirroring the `WalletStore::import` gate). Checksum failures map to
    /// `BadEnvelope`; the offending phrase is never retained.
    pub fn import(session: &SeedSession, phrase: &str) -> Result<Self, SeedCeremonyError> {
        session.require_up_pin()?;
        let mnemonic =
            Mnemonic24::from_phrase(phrase).map_err(|_| SeedCeremonyError::BadEnvelope)?;
        Ok(Self {
            mnemonic,
            backed_up: false,
        })
    }

    /// Restores a ceremony from a sealed envelope previously produced by
    /// [`SeedCeremony::export_sealed`] (gate UP+PIN). Wrong PIN token,
    /// tampered bytes, or malformed envelopes map to `BadEnvelope`,
    /// fail-closed, without distinguishing the cause.
    pub fn import_sealed(
        session: &SeedSession,
        vault: &AegisVault,
        pin_token: &[u8],
        envelope: &[u8],
    ) -> Result<Self, SeedCeremonyError> {
        session.require_up_pin()?;
        let mut entropy = vault
            .open_envelope(envelope, pin_token)
            .map_err(|_| SeedCeremonyError::BadEnvelope)?;
        if entropy.len() != 32 {
            entropy.zeroize();
            return Err(SeedCeremonyError::BadEnvelope);
        }
        let mut entropy32 = [0u8; 32];
        entropy32.copy_from_slice(&entropy);
        entropy.zeroize();
        let mnemonic =
            Mnemonic24::from_entropy(&entropy32).map_err(|_| SeedCeremonyError::BadEnvelope)?;
        entropy32.zeroize();
        Ok(Self {
            mnemonic,
            backed_up: false,
        })
    }

    /// Reveals the phrase for the physical display step of the ceremony
    /// (gate UP). The caller shows it and must never log or persist it;
    /// confirmation goes through [`SeedCeremony::confirm`].
    pub fn reveal_phrase(&self, session: &SeedSession) -> Result<&str, SeedCeremonyError> {
        session.require_up()?;
        Ok(self.mnemonic.phrase())
    }

    /// Confirms the physically displayed phrase (gate UP): the holder
    /// re-enters (or selects) the words and the ceremony accepts only an
    /// exact match. Mismatches map to `BadEnvelope`; nothing secret leaks
    /// in the error.
    pub fn confirm(&self, session: &SeedSession, candidate: &str) -> Result<(), SeedCeremonyError> {
        session.require_up()?;
        if candidate.trim() == self.mnemonic.phrase() {
            Ok(())
        } else {
            Err(SeedCeremonyError::BadEnvelope)
        }
    }

    /// Seals the 32-byte entropy with the existing PIN-bound vault envelope
    /// (AEGN `0x01`, same pair used by `WalletStore::import`) for the
    /// firmware persistence layer (gate UP+PIN). Returns opaque bytes: no
    /// private material is introspectable without the vault + PIN token.
    pub fn export_sealed<R: CryptoRng>(
        &self,
        session: &SeedSession,
        vault: &AegisVault,
        pin_token: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, SeedCeremonyError> {
        session.require_up_pin()?;
        vault
            .seal_envelope(self.mnemonic.entropy(), pin_token, rng)
            .map_err(|_| SeedCeremonyError::Storage)
    }

    /// Splits the entropy into 2-of-3 Shamir shares (gate UP+PIN) and marks
    /// the ceremony backed up. The caller owns share custody (device /
    /// backup authenticator / paper card); this call retains nothing.
    pub fn split_backup<R: CryptoRng>(
        &mut self,
        session: &SeedSession,
        rng: &mut R,
    ) -> Result<[ShamirShare; 3], SeedCeremonyError> {
        session.require_up_pin()?;
        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);
        let shares = split_secret_2_of_3(self.mnemonic.entropy(), &salt);
        salt.zeroize();
        self.backed_up = true;
        Ok(shares)
    }

    /// Recovers the 32-byte secret from any 2 distinct backup shares (gate
    /// UP+PIN, since the output is secret). Pair with
    /// [`SeedCeremony::restore_from_secret`] to reopen a ceremony; the
    /// caller must zeroize the returned array once imported.
    pub fn recover_secret(
        session: &SeedSession,
        a: &ShamirShare,
        b: &ShamirShare,
    ) -> Result<[u8; 32], SeedCeremonyError> {
        session.require_up_pin()?;
        recover_secret_from_2_shares(a, b).map_err(|_| SeedCeremonyError::BadEnvelope)
    }

    /// Opens a ceremony directly from a recovered 32-byte secret (gate
    /// UP+PIN). Completes the Shamir restore path without funnelling the
    /// secret through any other type.
    pub fn restore_from_secret(
        session: &SeedSession,
        secret: &[u8; 32],
    ) -> Result<Self, SeedCeremonyError> {
        session.require_up_pin()?;
        let mnemonic =
            Mnemonic24::from_entropy(secret).map_err(|_| SeedCeremonyError::BadEnvelope)?;
        Ok(Self {
            mnemonic,
            backed_up: true,
        })
    }

    /// Derives the [`AegisVault`] from the seed (`PBKDF2-HMAC-SHA512` 2048
    /// rounds + `HKDF-SHA256`, same pair as `Mnemonic24::to_seed` /
    /// `AegisVault::from_master_seed`) without ever exposing seed bytes
    /// (gate UP+PIN). Intermediate seed material is zeroized before return.
    pub fn to_vault(
        &self,
        session: &SeedSession,
        passphrase: &str,
    ) -> Result<AegisVault, SeedCeremonyError> {
        session.require_up_pin()?;
        let mut seed = self.mnemonic.to_seed(passphrase);
        let vault = AegisVault::from_master_seed(&seed).map_err(|_| SeedCeremonyError::Storage)?;
        seed.zeroize();
        Ok(vault)
    }

    /// Returns the public ceremony metadata (gate UP). Safe for wire
    /// `0x00` + metadata responses: no private bytes cross here.
    pub fn metadata(&self, session: &SeedSession) -> Result<SeedMetadata, SeedCeremonyError> {
        session.require_up()?;
        let mut hasher = Sha256::new();
        hasher.update(self.mnemonic.entropy());
        let digest = hasher.finalize();
        let mut fingerprint = [0u8; 8];
        fingerprint.copy_from_slice(&digest[..8]);
        Ok(SeedMetadata {
            word_count: SEED_WORD_COUNT,
            fingerprint,
            backed_up: self.backed_up,
        })
    }

    /// Ends the ceremony, zeroizing the phrase and entropy (drop glue in
    /// ceremony language; `Drop` via `ZeroizeOnDrop` covers plain drops).
    pub fn wipe(self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::VAULT_ENVELOPE_MIN_LEN;

    const OFFICIAL_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    const PIN: &[u8] = b"seed-ceremony-pin-token";

    fn up() -> SeedSession {
        SeedSession::authorize(true, false)
    }

    fn up_pin() -> SeedSession {
        SeedSession::authorize(true, true)
    }

    fn none_session() -> SeedSession {
        SeedSession::authorize(false, false)
    }

    #[test]
    fn should_gate_generate_on_up() {
        let mut rng = rand::rng();
        assert_eq!(
            SeedCeremony::generate(&none_session(), &mut rng).unwrap_err(),
            SeedCeremonyError::NeedUp
        );
        let ceremony = SeedCeremony::generate(&up(), &mut rng).unwrap();
        assert_eq!(ceremony.mnemonic.words().len(), 24);
    }

    #[test]
    fn should_gate_import_on_up_and_pin() {
        assert_eq!(
            SeedCeremony::import(&none_session(), OFFICIAL_PHRASE).unwrap_err(),
            SeedCeremonyError::NeedUp
        );
        assert_eq!(
            SeedCeremony::import(&up(), OFFICIAL_PHRASE).unwrap_err(),
            SeedCeremonyError::NeedPin
        );
        let ceremony = SeedCeremony::import(&up_pin(), OFFICIAL_PHRASE).unwrap();
        assert_eq!(ceremony.mnemonic.phrase(), OFFICIAL_PHRASE);
        assert_eq!(ceremony.mnemonic.entropy(), &[0u8; 32]);
    }

    #[test]
    fn should_reject_bad_phrase_without_retaining_it() {
        assert_eq!(
            SeedCeremony::import(&up_pin(), "abandon abandon").unwrap_err(),
            SeedCeremonyError::BadEnvelope
        );
        let mut corrupted = String::from(OFFICIAL_PHRASE);
        corrupted.push_str(" extra");
        assert_eq!(
            SeedCeremony::import(&up_pin(), &corrupted).unwrap_err(),
            SeedCeremonyError::BadEnvelope
        );
    }

    #[test]
    fn should_confirm_only_exact_phrase() {
        let ceremony = SeedCeremony::import(&up_pin(), OFFICIAL_PHRASE).unwrap();
        assert_eq!(
            ceremony
                .confirm(&none_session(), OFFICIAL_PHRASE)
                .unwrap_err(),
            SeedCeremonyError::NeedUp
        );
        ceremony.confirm(&up(), OFFICIAL_PHRASE).unwrap();
        assert_eq!(
            ceremony.confirm(&up(), "abandon abandon").unwrap_err(),
            SeedCeremonyError::BadEnvelope
        );
    }

    #[test]
    fn should_reveal_phrase_only_with_up() {
        let ceremony = SeedCeremony::import(&up_pin(), OFFICIAL_PHRASE).unwrap();
        assert_eq!(
            ceremony.reveal_phrase(&none_session()).unwrap_err(),
            SeedCeremonyError::NeedUp
        );
        assert_eq!(ceremony.reveal_phrase(&up()).unwrap(), OFFICIAL_PHRASE);
    }

    #[test]
    fn should_seal_and_reopen_roundtrip_and_reject_wrong_pin() {
        let mut rng = rand::rng();
        let vault = AegisVault::new([0x5Au8; 32]);
        let ceremony = SeedCeremony::import(&up_pin(), OFFICIAL_PHRASE).unwrap();
        assert_eq!(
            ceremony
                .export_sealed(&up(), &vault, PIN, &mut rng)
                .unwrap_err(),
            SeedCeremonyError::NeedPin
        );
        let sealed = ceremony
            .export_sealed(&up_pin(), &vault, PIN, &mut rng)
            .unwrap();
        assert!(sealed.len() >= VAULT_ENVELOPE_MIN_LEN);
        let reopened = SeedCeremony::import_sealed(&up_pin(), &vault, PIN, &sealed).unwrap();
        assert_eq!(reopened.mnemonic.phrase(), OFFICIAL_PHRASE);
        assert_eq!(
            SeedCeremony::import_sealed(&up_pin(), &vault, b"wrong-pin", &sealed).unwrap_err(),
            SeedCeremonyError::BadEnvelope
        );
        let mut tampered = sealed.clone();
        tampered[20] ^= 0x55;
        assert_eq!(
            SeedCeremony::import_sealed(&up_pin(), &vault, PIN, &tampered).unwrap_err(),
            SeedCeremonyError::BadEnvelope
        );
        assert_eq!(
            SeedCeremony::import_sealed(&up_pin(), &vault, PIN, b"short").unwrap_err(),
            SeedCeremonyError::BadEnvelope
        );
    }

    #[test]
    fn should_split_and_recover_all_share_pairs() {
        let mut rng = rand::rng();
        let mut ceremony = SeedCeremony::import(&up_pin(), OFFICIAL_PHRASE).unwrap();
        assert_eq!(
            ceremony.split_backup(&up(), &mut rng).unwrap_err(),
            SeedCeremonyError::NeedPin
        );
        let shares = ceremony.split_backup(&up_pin(), &mut rng).unwrap();
        assert!(ceremony.metadata(&up()).unwrap().backed_up);
        for (a, b) in [
            (&shares[0], &shares[1]),
            (&shares[0], &shares[2]),
            (&shares[1], &shares[2]),
        ] {
            let secret = SeedCeremony::recover_secret(&up_pin(), a, b).unwrap();
            assert_eq!(secret, [0u8; 32]);
            let restored = SeedCeremony::restore_from_secret(&up_pin(), &secret).unwrap();
            assert_eq!(restored.mnemonic.phrase(), OFFICIAL_PHRASE);
        }
        assert_eq!(
            SeedCeremony::recover_secret(&up_pin(), &shares[0], &shares[0]).unwrap_err(),
            SeedCeremonyError::BadEnvelope
        );
        let mut tampered = shares[1].clone();
        tampered.data[5] ^= 0x01;
        assert_eq!(
            SeedCeremony::recover_secret(&up_pin(), &shares[0], &tampered).unwrap_err(),
            SeedCeremonyError::BadEnvelope
        );
        assert_eq!(
            SeedCeremony::recover_secret(&up(), &shares[0], &shares[1]).unwrap_err(),
            SeedCeremonyError::NeedPin
        );
    }

    #[test]
    fn should_derive_vault_without_exposing_seed() {
        let ceremony = SeedCeremony::import(&up_pin(), OFFICIAL_PHRASE).unwrap();
        assert_eq!(
            ceremony.to_vault(&up(), "").unwrap_err(),
            SeedCeremonyError::NeedPin
        );
        let vault = ceremony.to_vault(&up_pin(), "TREZOR").unwrap();
        let expected = AegisVault::from_master_seed(&ceremony.mnemonic.to_seed("TREZOR")).unwrap();
        assert_eq!(vault.len(), expected.len());
    }

    #[test]
    fn should_report_public_metadata_only() {
        let ceremony = SeedCeremony::import(&up_pin(), OFFICIAL_PHRASE).unwrap();
        assert_eq!(
            ceremony.metadata(&none_session()).unwrap_err(),
            SeedCeremonyError::NeedUp
        );
        let meta = ceremony.metadata(&up()).unwrap();
        assert_eq!(meta.word_count, 24);
        assert!(!meta.backed_up);
        let mut hasher = Sha256::new();
        hasher.update([0u8; 32]);
        let digest = hasher.finalize();
        assert_eq!(&meta.fingerprint, &digest[..8]);
        let dbg = alloc::format!("{:?}", ceremony);
        assert!(!dbg.contains("abandon"));
        let meta_dbg = alloc::format!("{:?}", meta);
        assert!(!meta_dbg.contains("abandon"));
    }

    #[test]
    fn should_map_errors_to_closed_wire_statuses() {
        assert_eq!(SeedCeremonyError::NeedUp.status(), STATUS_NEED_UP);
        assert_eq!(SeedCeremonyError::NeedPin.status(), STATUS_NEED_PIN);
        assert_eq!(SeedCeremonyError::BadEnvelope.status(), STATUS_BAD_ENVELOPE);
        assert_eq!(SeedCeremonyError::Storage.status(), STATUS_BAD_ENVELOPE);
        assert_eq!(
            alloc::format!("{}", SeedCeremonyError::NeedUp),
            "seed ceremony requires user presence"
        );
    }
}
