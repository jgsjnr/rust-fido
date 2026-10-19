extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use rand_core::RngCore;
use zeroize::Zeroize;

use crate::crypto::hash::sha256;
use crate::policy::{PolicyError, UpAndPin, UpOnly, UpPolicy};
#[cfg(feature = "debug-terminal")]
use crate::lifetime::{LifetimeCategory as LtCat, LifetimeEvent as LtEvt};

use super::crypto::{calculate_code, calculate_code_from_challenge, pbkdf2_sha1, verify_challenge_response};
use super::presence::PresenceVerifier;
use super::tlv::{find_tlv, parse_tlv_records, write_tlv};
use super::types::*;

/// Version reported by the AegisKey OATH applet (YKOATH v5.4.3 compatible)
pub const APPLET_VERSION: [u8; 3] = [0x05, 0x04, 0x03];

/// Maximum number of OATH credentials stored in device
pub const MAX_CREDENTIALS: usize = 64;
/// Fase6 — alias de slots OATH (§9 limite MAX_CREDENTIALS=64).
pub const MAX_OATH_SLOTS: usize = MAX_CREDENTIALS;
/// Fase6 — bounds do label OATH (§9.3 label 1..32B utf8).
pub const MAX_OATH_LABEL_BYTES: usize = 32;
pub const MIN_OATH_LABEL_BYTES: usize = 1;
/// Fase6 — periodo TOTP em segundos (§7 janela 30s, RFC6238).
pub const OATH_PERIOD_SECS: u32 = 30;
/// Fase6 — digitos permitidos (§7 6-8 digitos, zero-padded).
pub const MIN_OATH_DIGITS: u8 = 6;
pub const MAX_OATH_DIGITS: u8 = 8;

/// Fase6 Step3 - limite TLV inner (9.3 TLV total <=512B).
pub const OATH_TLV_MAX_BYTES: usize = 512;
/// Fase6 Step3 - journal HOTP (shape sign_count: magic+seq+n+entries+checksum).
pub const HOTP_JOURNAL_MAGIC: u32 = 0x4F484A31;
/// Fase6 Step3 - maximo de entradas no journal HOTP (=MAX_CREDENTIALS).
pub const HOTP_JOURNAL_MAX_ENTRIES: usize = MAX_CREDENTIALS;

/// Fase6 Step3 - erros fechados BLE 9.5 (0x01-0x04, payload erro = 0B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OathDeviceError {
    NeedUp = 0x01,
    NeedPin = 0x02,
    NoSlot = 0x03,
    BadEnvelope = 0x04,
}

impl OathDeviceError {
    pub fn code(self) -> u8 {
        self as u8
    }
}

impl From<PolicyError> for OathDeviceError {
    fn from(e: PolicyError) -> Self {
        match e {
            PolicyError::PresenceRequired => Self::NeedUp,
            PolicyError::PinRequired => Self::NeedPin,
        }
    }
}

/// Fase6 Step3 - resultado CODE (so codigo; secret nunca sai, 9.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OathCodeResult {
    pub code: String,
    pub digits: u8,
}

/// Fase6 — metadados OATH sobre BLE (secret nunca sai; §9.7 so codigo).
/// Reutiliza `OathAlgorithm`/`OathType` existentes, sem nova cripto.
#[derive(Debug, Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct OathSlot {
    /// Rotulo utf8 1..32B (§9.2 tag 0x71 NAME).
    pub label: String,
    /// Algoritmo HMAC (tag 0x73 type_algo).
    pub hmac: OathAlgorithm,
    /// Tipo HOTP/TOTP (tag 0x73 type_algo).
    pub tipo: OathType,
    /// Contador HOTP (TOTP usa challenge; tag 0x7A IMF).
    pub contador: u64,
    /// Digitos 6..=8.
    pub digits: u8,
    /// Periodo TOTP (30s).
    pub periodo: u32,
}

impl OathSlot {
    /// Cria slot validando bounds §9.3/§7.
    pub fn new(label: String, hmac: OathAlgorithm, tipo: OathType, contador: u64, digits: u8, periodo: u32) -> Result<Self, &'static str> {
        let n = label.len();
        if !(MIN_OATH_LABEL_BYTES..=MAX_OATH_LABEL_BYTES).contains(&n) {
            return Err("bad label");
        }
        if !(MIN_OATH_DIGITS..=MAX_OATH_DIGITS).contains(&digits) {
            return Err("bad digits");
        }
        if periodo != OATH_PERIOD_SECS {
            return Err("bad periodo");
        }
        Ok(Self { label, hmac, tipo, contador, digits, periodo })
    }

    /// Converte de `OathCredential` existente (preserva semantica `OathApplet`).
    pub fn from_credential(c: &OathCredential) -> Result<Self, &'static str> {
        Self::new(c.name.clone(), c.algorithm, c.oath_type, c.counter, c.digits, OATH_PERIOD_SECS)
    }
}

/// AegisKey YKOATH Applet implementation
pub struct OathApplet {
    pub credentials: Vec<OathCredential>,
    pub salt: [u8; 8],
    pub has_password: bool,
    pub key: [u8; 16],
    pub authenticated: bool,
    pub current_challenge: [u8; 8],
    pub hotp_seq: u32,
}

impl Default for OathApplet {
    fn default() -> Self {
        Self::new()
    }
}

impl OathApplet {
    /// Create a new OATH applet instance
    pub fn new() -> Self {
        Self {
            credentials: Vec::new(),
            salt: [0x53, 0x41, 0x4C, 0x54, 0x30, 0x30, 0x30, 0x31], // "SALT0001" default salt
            has_password: false,
            key: [0u8; 16],
            authenticated: true, // If no password set, always authenticated
            current_challenge: [0u8; 8],
            hotp_seq: 0,
        }
    }

    /// Set an explicit 8-byte salt (e.g. derived from device serial or flash)
    pub fn set_salt(&mut self, salt: [u8; 8]) {
        self.salt = salt;
    }

    /// Check if the session is currently authenticated
    pub fn is_authenticated(&self) -> bool {
        !self.has_password || self.authenticated
    }

    /// Set password directly (uses PBKDF2-SHA1 to derive the 16-byte key)
    pub fn set_password(&mut self, password: &[u8]) {
        let derived = pbkdf2_sha1(password, &self.salt, 1000, 16);
        self.key.copy_from_slice(&derived);
        self.has_password = true;
        self.authenticated = false;
    }

    /// Clear password protection
    pub fn clear_password(&mut self) {
        self.has_password = false;
        self.key.fill(0);
        self.authenticated = true;
    }

    /// Process an incoming raw APDU command
    pub fn handle_apdu<R: RngCore, P: PresenceVerifier>(
        &mut self,
        apdu: &[u8],
        rng: &mut R,
        presence: &mut P,
    ) -> (Vec<u8>, u16) {
        if apdu.len() < 4 {
            return (Vec::new(), SW_WRONG_DATA);
        }

        let cla = apdu[0];
        let ins = apdu[1];
        let p1 = apdu[2];
        let p2 = apdu[3];

        if cla != 0x00 {
            return (Vec::new(), SW_CLA_NOT_SUPPORTED);
        }

        let data = if apdu.len() > 5 {
            let lc = apdu[4] as usize;
            if 5 + lc <= apdu.len() {
                &apdu[5..5 + lc]
            } else {
                &apdu[5..]
            }
        } else {
            &[]
        };

        match ins {
            INS_SELECT if p1 == 0x04 => self.handle_select(data, rng),
            INS_VALIDATE => self.handle_validate(data),
            INS_PUT => self.handle_put(data),
            INS_DELETE => self.handle_delete(data),
            INS_SET_CODE => self.handle_set_code(data),
            INS_RESET => self.handle_reset(),
            INS_LIST => self.handle_list(),
            INS_CALCULATE => self.handle_calculate(p2, data, presence),
            INS_CALCULATE_ALL => self.handle_calculate_all(p2, data),
            _ => (Vec::new(), SW_INS_NOT_SUPPORTED),
        }
    }

    /// Handle SELECT command (AID matching)
    fn handle_select<R: RngCore>(&mut self, aid: &[u8], rng: &mut R) -> (Vec<u8>, u16) {
        // Accept matching YKOATH AID or prefix
        if aid.len() >= 7 && aid[..7] == YKOATH_AID {
            let mut resp = Vec::new();

            // Tag 0x79: Version
            write_tlv(&mut resp, TAG_VERSION, &APPLET_VERSION);

            // Tag 0x71: Device salt / identifier
            write_tlv(&mut resp, TAG_NAME, &self.salt);

            // Tag 0x74: Challenge (if password is set, generate and return 8-byte challenge)
            if self.has_password {
                rng.fill_bytes(&mut self.current_challenge);
                self.authenticated = false;
                write_tlv(&mut resp, TAG_CHALLENGE, &self.current_challenge);
            } else {
                self.authenticated = true;
            }

            // Tag 0x7B: Supported algorithms (SHA1, SHA256, SHA512)
            write_tlv(&mut resp, TAG_ALGORITHM, &[0x01, 0x02, 0x03]);

            (resp, SW_SUCCESS)
        } else {
            (Vec::new(), SW_DATA_NOT_FOUND)
        }
    }

    /// Handle VALIDATE command (host unlocks applet using challenge response)
    fn handle_validate(&mut self, data: &[u8]) -> (Vec<u8>, u16) {
        if !self.has_password {
            self.authenticated = true;
            return (Vec::new(), SW_SUCCESS);
        }

        let records = match parse_tlv_records(data) {
            Ok(r) => r,
            Err(e) => return (Vec::new(), e.to_sw()),
        };

        let response = match find_tlv(&records, TAG_RESPONSE) {
            Some(resp) => resp,
            None => return (Vec::new(), SW_WRONG_DATA),
        };

        if verify_challenge_response(&self.key, &self.current_challenge, response) {
            self.authenticated = true;
            (Vec::new(), SW_SUCCESS)
        } else {
            self.authenticated = false;
            (Vec::new(), SW_SECURITY_STATUS_NOT_SATISFIED)
        }
    }

    /// Handle PUT command (create or update credential)
    fn handle_put(&mut self, data: &[u8]) -> (Vec<u8>, u16) {
        if !self.is_authenticated() {
            return (Vec::new(), SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        let records = match parse_tlv_records(data) {
            Ok(r) => r,
            Err(e) => return (Vec::new(), e.to_sw()),
        };

        let name_bytes = match find_tlv(&records, TAG_NAME) {
            Some(n) => n,
            None => return (Vec::new(), SW_WRONG_DATA),
        };

        let name = match core::str::from_utf8(name_bytes) {
            Ok(s) => s.to_string(),
            Err(_) => return (Vec::new(), SW_WRONG_DATA),
        };

        let key_bytes = match find_tlv(&records, TAG_KEY) {
            Some(k) if k.len() >= 2 => k,
            _ => return (Vec::new(), SW_WRONG_DATA),
        };

        let type_algo = key_bytes[0];
        let digits = key_bytes[1];
        let secret = key_bytes[2..].to_vec();

        let oath_type = match OathType::from_u8(type_algo & 0xF0) {
            Some(t) => t,
            None => return (Vec::new(), SW_WRONG_DATA),
        };

        let algorithm = match OathAlgorithm::from_u8(type_algo & 0x0F) {
            Some(a) => a,
            None => return (Vec::new(), SW_WRONG_DATA),
        };

        let touch_required = match find_tlv(&records, TAG_PROPERTY) {
            Some(prop) => !prop.is_empty() && (prop[0] & 0x01) != 0,
            None => false,
        };

        let counter = match find_tlv(&records, TAG_IMF) {
            Some(imf) if imf.len() == 4 => {
                u32::from_be_bytes([imf[0], imf[1], imf[2], imf[3]]) as u64
            }
            _ => 0,
        };

        if let Some(existing) = self.credentials.iter_mut().find(|c| c.name == name) {
            existing.secret = secret;
            existing.algorithm = algorithm;
            existing.digits = digits;
            existing.oath_type = oath_type;
            existing.counter = counter;
            existing.touch_required = touch_required;
        } else {
            if self.credentials.len() >= MAX_CREDENTIALS {
                return (Vec::new(), SW_FILE_FULL);
            }
            self.credentials.push(OathCredential::new(
                name,
                secret,
                algorithm,
                digits,
                oath_type,
                counter,
                touch_required,
            ));
        }

        (Vec::new(), SW_SUCCESS)
    }

    /// Handle DELETE command
    fn handle_delete(&mut self, data: &[u8]) -> (Vec<u8>, u16) {
        if !self.is_authenticated() {
            return (Vec::new(), SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        let records = match parse_tlv_records(data) {
            Ok(r) => r,
            Err(e) => return (Vec::new(), e.to_sw()),
        };

        let name_bytes = match find_tlv(&records, TAG_NAME) {
            Some(n) => n,
            None => return (Vec::new(), SW_WRONG_DATA),
        };

        let name = match core::str::from_utf8(name_bytes) {
            Ok(s) => s,
            Err(_) => return (Vec::new(), SW_WRONG_DATA),
        };

        if let Some(pos) = self.credentials.iter().position(|c| c.name == name) {
            self.credentials.remove(pos);
            (Vec::new(), SW_SUCCESS)
        } else {
            (Vec::new(), SW_DATA_NOT_FOUND)
        }
    }

    /// Handle SET CODE command (set/clear password)
    fn handle_set_code(&mut self, data: &[u8]) -> (Vec<u8>, u16) {
        if !self.is_authenticated() {
            return (Vec::new(), SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        let records = match parse_tlv_records(data) {
            Ok(r) => r,
            Err(e) => return (Vec::new(), e.to_sw()),
        };

        match find_tlv(&records, TAG_KEY) {
            Some(key_bytes) if !key_bytes.is_empty() => {
                if key_bytes.len() == 16 {
                    self.key.copy_from_slice(key_bytes);
                    self.has_password = true;
                    self.authenticated = true;
                    (Vec::new(), SW_SUCCESS)
                } else {
                    (Vec::new(), SW_WRONG_DATA)
                }
            }
            _ => {
                // Empty key clears the password
                self.clear_password();
                (Vec::new(), SW_SUCCESS)
            }
        }
    }

    /// Handle RESET command (wipe credentials and reset state)
    fn handle_reset(&mut self) -> (Vec<u8>, u16) {
        self.credentials.clear();
        self.clear_password();
        (Vec::new(), SW_SUCCESS)
    }

    /// Handle LIST command (list all credential names with type/algo byte)
    fn handle_list(&self) -> (Vec<u8>, u16) {
        if !self.is_authenticated() {
            return (Vec::new(), SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        let mut resp = Vec::new();
        for cred in &self.credentials {
            let mut val = Vec::with_capacity(1 + cred.name.len());
            val.push(cred.type_algo_byte());
            val.extend_from_slice(cred.name.as_bytes());
            write_tlv(&mut resp, TAG_NAME, &val);
        }

        (resp, SW_SUCCESS)
    }

    /// Handle CALCULATE command (calculate code for a single credential)
    fn handle_calculate<P: PresenceVerifier>(
        &mut self,
        p2: u8,
        data: &[u8],
        presence: &mut P,
    ) -> (Vec<u8>, u16) {
        if !self.is_authenticated() {
            return (Vec::new(), SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        let records = match parse_tlv_records(data) {
            Ok(r) => r,
            Err(e) => return (Vec::new(), e.to_sw()),
        };

        let name_bytes = match find_tlv(&records, TAG_NAME) {
            Some(n) => n,
            None => return (Vec::new(), SW_WRONG_DATA),
        };

        let name = match core::str::from_utf8(name_bytes) {
            Ok(s) => s,
            Err(_) => return (Vec::new(), SW_WRONG_DATA),
        };

        let challenge = find_tlv(&records, TAG_CHALLENGE);

        let cred = match self.credentials.iter_mut().find(|c| c.name == name) {
            Some(c) => c,
            None => return (Vec::new(), SW_DATA_NOT_FOUND),
        };

        // If touch required, verify user presence (e.g., button touch)
        if cred.touch_required {
            match presence.wait_for_presence(3000) {
                Ok(true) => {}
                _ => {
                    let mut resp = Vec::new();
                    write_tlv(&mut resp, TAG_TOUCH, &[]);
                    return (resp, SW_CONDITIONS_NOT_SATISFIED);
                }
            }
        }

        let code = match cred.oath_type {
            OathType::Totp => {
                let chal = match challenge {
                    Some(c) => c,
                    None => return (Vec::new(), SW_WRONG_DATA),
                };
                calculate_code_from_challenge(cred.algorithm, &cred.secret, chal, cred.digits)
            }
            OathType::Hotp => {
                let c = cred.counter;
                cred.counter += 1;
                calculate_code(cred.algorithm, &cred.secret, c, cred.digits)
            }
        };

        let mut resp = Vec::new();
        let code_bytes = code.to_be_bytes();

        if p2 == 0x01 {
            // Truncated response: digits byte + 4 bytes code
            let mut val = [0u8; 5];
            val[0] = cred.digits;
            val[1..5].copy_from_slice(&code_bytes);
            write_tlv(&mut resp, TAG_TRUNCATED_RESPONSE, &val);
        } else {
            // Full 4-byte response
            write_tlv(&mut resp, TAG_RESPONSE, &code_bytes);
        }

        (resp, SW_SUCCESS)
    }

    /// Handle CALCULATE ALL command (batch calculate TOTP codes)
    fn handle_calculate_all(&mut self, p2: u8, data: &[u8]) -> (Vec<u8>, u16) {
        if !self.is_authenticated() {
            return (Vec::new(), SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        let records = match parse_tlv_records(data) {
            Ok(r) => r,
            Err(e) => return (Vec::new(), e.to_sw()),
        };

        let challenge = match find_tlv(&records, TAG_CHALLENGE) {
            Some(c) => c,
            None => return (Vec::new(), SW_WRONG_DATA),
        };

        let mut resp = Vec::new();

        for cred in &mut self.credentials {
            // Output Tag 0x71: Name
            write_tlv(&mut resp, TAG_NAME, cred.name.as_bytes());

            if cred.touch_required {
                // If touch required, output Tag 0x7C without the code
                write_tlv(&mut resp, TAG_TOUCH, &[]);
            } else {
                let code = match cred.oath_type {
                    OathType::Totp => {
                        calculate_code_from_challenge(cred.algorithm, &cred.secret, challenge, cred.digits)
                    }
                    OathType::Hotp => {
                        // In CALCULATE ALL, HOTP codes are not auto-incremented
                        calculate_code(cred.algorithm, &cred.secret, cred.counter, cred.digits)
                    }
                };

                let code_bytes = code.to_be_bytes();
                if p2 == 0x01 {
                    let mut val = [0u8; 5];
                    val[0] = cred.digits;
                    val[1..5].copy_from_slice(&code_bytes);
                    write_tlv(&mut resp, TAG_TRUNCATED_RESPONSE, &val);
                } else {
                    write_tlv(&mut resp, TAG_RESPONSE, &code_bytes);
                }
            }
        }

        (resp, SW_SUCCESS)
    }
}

/// Fase6 Step3 - device layer BLE (9.3/9.4) sobre OathApplet.
///
/// Gates: PUT=UP+PIN, LIST=UP, CODE=UP, DELETE=UP+PIN.
/// TLV total <=512; HOTP atomico via &mut; challenge TOTP exatamente 8B;
/// 65a cred -> NoSlot. Sem getter de segredo: LIST retorna OathSlot
/// (metadados), CODE retorna so codigo.
impl OathApplet {
    /// PUT (9.3 0x71+0x73+opt 0x78/0x7A): cria ou atualiza; exige UP+PIN.
    pub fn device_put(
        &mut self,
        request_tlv: &[u8],
        pin_authenticated: bool,
        presence_confirmed: bool,
    ) -> Result<(), OathDeviceError> {
        UpAndPin.check_up(pin_authenticated, presence_confirmed)?;
        if request_tlv.len() > OATH_TLV_MAX_BYTES {
            return Err(OathDeviceError::BadEnvelope);
        }
        let records =
            parse_tlv_records(request_tlv).map_err(|_| OathDeviceError::BadEnvelope)?;
        let name_bytes = find_tlv(&records, TAG_NAME).ok_or(OathDeviceError::BadEnvelope)?;
        if name_bytes.is_empty() || name_bytes.len() > MAX_OATH_LABEL_BYTES {
            return Err(OathDeviceError::BadEnvelope);
        }
        let name =
            core::str::from_utf8(name_bytes).map_err(|_| OathDeviceError::BadEnvelope)?;
        let key_bytes = find_tlv(&records, TAG_KEY).ok_or(OathDeviceError::BadEnvelope)?;
        if key_bytes.len() < 3 {
            return Err(OathDeviceError::BadEnvelope);
        }
        let type_algo = key_bytes[0];
        let digits = key_bytes[1];
        if !(MIN_OATH_DIGITS..=MAX_OATH_DIGITS).contains(&digits) {
            return Err(OathDeviceError::BadEnvelope);
        }
        let secret = &key_bytes[2..];
        if secret.is_empty() {
            return Err(OathDeviceError::BadEnvelope);
        }
        let oath_type =
            OathType::from_u8(type_algo & 0xF0).ok_or(OathDeviceError::BadEnvelope)?;
        let algorithm =
            OathAlgorithm::from_u8(type_algo & 0x0F).ok_or(OathDeviceError::BadEnvelope)?;
        let touch_required = match find_tlv(&records, TAG_PROPERTY) {
            Some(prop) => !prop.is_empty() && (prop[0] & 0x01) != 0,
            None => false,
        };
        let counter = match find_tlv(&records, TAG_IMF) {
            Some(imf) => {
                if imf.len() != 4 {
                    return Err(OathDeviceError::BadEnvelope);
                }
                u32::from_be_bytes([imf[0], imf[1], imf[2], imf[3]]) as u64
            }
            None => 0,
        };
        if let Some(existing) = self.credentials.iter_mut().find(|c| c.name == name) {
            existing.secret.zeroize();
            existing.secret = secret.to_vec();
            existing.algorithm = algorithm;
            existing.digits = digits;
            existing.oath_type = oath_type;
            existing.counter = counter;
            existing.touch_required = touch_required;
        } else {
            if self.credentials.len() >= MAX_CREDENTIALS {
                return Err(OathDeviceError::NoSlot);
            }
            self.credentials.push(OathCredential::new(
                name.to_string(),
                secret.to_vec(),
                algorithm,
                digits,
                oath_type,
                counter,
                touch_required,
            ));
        }
        crate::ltrace!(LtCat::Oath, LtEvt::OathPut, name);
        Ok(())
    }

    /// LIST (9.3 vazio -> repeticao 0x71): so metadados OathSlot; exige UP.
    pub fn device_list(
        &self,
        _pin_authenticated: bool,
        presence_confirmed: bool,
    ) -> Result<Vec<OathSlot>, OathDeviceError> {
        UpOnly.check_up(false, presence_confirmed)?;
        let mut out = Vec::new();
        for c in &self.credentials {
            let s =
                OathSlot::from_credential(c).map_err(|_| OathDeviceError::BadEnvelope)?;
            out.push(s);
        }
        Ok(out)
    }

    /// CODE (9.3 0x71+opt 0x74): TOTP exige challenge 8B; HOTP atomico; UP.
    pub fn device_code(
        &mut self,
        request_tlv: &[u8],
        _pin_authenticated: bool,
        presence_confirmed: bool,
    ) -> Result<OathCodeResult, OathDeviceError> {
        UpOnly.check_up(false, presence_confirmed)?;
        if request_tlv.len() > OATH_TLV_MAX_BYTES {
            return Err(OathDeviceError::BadEnvelope);
        }
        let records =
            parse_tlv_records(request_tlv).map_err(|_| OathDeviceError::BadEnvelope)?;
        let name_bytes = find_tlv(&records, TAG_NAME).ok_or(OathDeviceError::BadEnvelope)?;
        if name_bytes.is_empty() || name_bytes.len() > MAX_OATH_LABEL_BYTES {
            return Err(OathDeviceError::BadEnvelope);
        }
        let name =
            core::str::from_utf8(name_bytes).map_err(|_| OathDeviceError::BadEnvelope)?;
        let cred = self
            .credentials
            .iter_mut()
            .find(|c| c.name == name)
            .ok_or(OathDeviceError::NoSlot)?;
        if cred.digits < MIN_OATH_DIGITS || cred.digits > MAX_OATH_DIGITS {
            return Err(OathDeviceError::BadEnvelope);
        }
        let code_u32 = match cred.oath_type {
            OathType::Totp => {
                let chal =
                    find_tlv(&records, TAG_CHALLENGE).ok_or(OathDeviceError::BadEnvelope)?;
                if chal.len() != 8 {
                    return Err(OathDeviceError::BadEnvelope);
                }
                calculate_code_from_challenge(cred.algorithm, &cred.secret, chal, cred.digits)
            }
            OathType::Hotp => {
                let c = cred.counter;
                cred.counter = cred.counter.wrapping_add(1);
                self.hotp_seq = self.hotp_seq.saturating_add(1);
                calculate_code(cred.algorithm, &cred.secret, c, cred.digits)
            }
        };
        let width = cred.digits as usize;
        let mut s = format!("{:0>width$}", code_u32, width = width);
        if s.len() > width {
            s = s[s.len() - width..].to_string();
        }
        crate::ltrace!(LtCat::Oath, LtEvt::OathCode, name);
        Ok(OathCodeResult {
            code: s,
            digits: cred.digits,
        })
    }

    /// DELETE (9.3 0x71): wipe secret.zeroize() + remove; exige UP+PIN.
    pub fn device_delete(
        &mut self,
        request_tlv: &[u8],
        pin_authenticated: bool,
        presence_confirmed: bool,
    ) -> Result<(), OathDeviceError> {
        UpAndPin.check_up(pin_authenticated, presence_confirmed)?;
        if request_tlv.len() > OATH_TLV_MAX_BYTES {
            return Err(OathDeviceError::BadEnvelope);
        }
        let records =
            parse_tlv_records(request_tlv).map_err(|_| OathDeviceError::BadEnvelope)?;
        let name_bytes = find_tlv(&records, TAG_NAME).ok_or(OathDeviceError::BadEnvelope)?;
        if name_bytes.is_empty() || name_bytes.len() > MAX_OATH_LABEL_BYTES {
            return Err(OathDeviceError::BadEnvelope);
        }
        let name =
            core::str::from_utf8(name_bytes).map_err(|_| OathDeviceError::BadEnvelope)?;
        let pos = self
            .credentials
            .iter()
            .position(|c| c.name == name)
            .ok_or(OathDeviceError::NoSlot)?;
        self.credentials[pos].secret.zeroize();
        self.credentials.remove(pos);
        crate::ltrace!(LtCat::Oath, LtEvt::OathDelete, name);
        Ok(())
    }

    /// Exporta contadores HOTP (shape sign_count: magic+seq+n+entries+sum).
    /// So HOTP; entries = sha256(label) 32B + counter 8B BE. Monotonico.
    pub fn export_hotp_counts(&self) -> Vec<u8> {
        let mut entries: Vec<([u8; 32], u64)> = Vec::new();
        for c in &self.credentials {
            if c.oath_type == OathType::Hotp {
                entries.push((sha256(c.name.as_bytes()), c.counter));
                if entries.len() >= HOTP_JOURNAL_MAX_ENTRIES {
                    break;
                }
            }
        }
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&HOTP_JOURNAL_MAGIC.to_be_bytes());
        body.extend_from_slice(&self.hotp_seq.to_be_bytes());
        body.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        for (h, v) in &entries {
            body.extend_from_slice(h);
            body.extend_from_slice(&v.to_be_bytes());
        }
        let mut sum: u32 = 0;
        for b in body.iter() {
            sum = sum.wrapping_add(*b as u32);
        }
        body.extend_from_slice(&sum.to_be_bytes());
        body
    }

    /// Importa contadores HOTP: so avanca (nunca reduz); desconhecidos ignorados.
    /// Formato invalido -> BadEnvelope (conjunto fechado 9.5).
    pub fn import_hotp_counts(&mut self, blob: &[u8]) -> Result<(), OathDeviceError> {
        if blob.len() < 12 {
            return Err(OathDeviceError::BadEnvelope);
        }
        let magic = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]);
        if magic != HOTP_JOURNAL_MAGIC {
            return Err(OathDeviceError::BadEnvelope);
        }
        let seq = u32::from_be_bytes([blob[4], blob[5], blob[6], blob[7]]);
        let n = u16::from_be_bytes([blob[8], blob[9]]) as usize;
        if n > HOTP_JOURNAL_MAX_ENTRIES {
            return Err(OathDeviceError::BadEnvelope);
        }
        let expect = 10 + n * 40 + 4;
        if blob.len() < expect {
            return Err(OathDeviceError::BadEnvelope);
        }
        let mut sum: u32 = 0;
        for b in blob[..expect - 4].iter() {
            sum = sum.wrapping_add(*b as u32);
        }
        let want = u32::from_be_bytes([
            blob[expect - 4],
            blob[expect - 3],
            blob[expect - 2],
            blob[expect - 1],
        ]);
        if sum != want {
            return Err(OathDeviceError::BadEnvelope);
        }
        let mut off = 10;
        for _ in 0..n {
            let mut h = [0u8; 32];
            h.copy_from_slice(&blob[off..off + 32]);
            off += 32;
            let v = u64::from_be_bytes([
                blob[off],
                blob[off + 1],
                blob[off + 2],
                blob[off + 3],
                blob[off + 4],
                blob[off + 5],
                blob[off + 6],
                blob[off + 7],
            ]);
            off += 8;
            for c in self.credentials.iter_mut() {
                if c.oath_type == OathType::Hotp && sha256(c.name.as_bytes()) == h {
                    if v > c.counter {
                        c.counter = v;
                    }
                    break;
                }
            }
        }
        if seq > self.hotp_seq {
            self.hotp_seq = seq;
        }
        Ok(())
    }
}
#[cfg(test)]
mod fase6_tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec;

    fn lbl(s: &str) -> String { String::from(s) }

    #[test]
    fn oathslot_bounds_fase6() {
        let ok = OathSlot::new(lbl("GitHub:alice"), OathAlgorithm::Sha1, OathType::Totp, 0, 6, OATH_PERIOD_SECS).unwrap();
        assert_eq!(ok.digits, 6);
        assert!(OathSlot::new(lbl(""), OathAlgorithm::Sha1, OathType::Totp, 0, 6, OATH_PERIOD_SECS).is_err());
        let big = String::from_utf8(vec![b'x'; MAX_OATH_LABEL_BYTES + 1]).unwrap();
        assert!(OathSlot::new(big, OathAlgorithm::Sha1, OathType::Totp, 0, 6, OATH_PERIOD_SECS).is_err());
        assert!(OathSlot::new(lbl("a"), OathAlgorithm::Sha1, OathType::Totp, 0, 5, OATH_PERIOD_SECS).is_err());
        assert!(OathSlot::new(lbl("a"), OathAlgorithm::Sha1, OathType::Totp, 0, 9, OATH_PERIOD_SECS).is_err());
        assert!(OathSlot::new(lbl("a"), OathAlgorithm::Sha1, OathType::Totp, 0, 6, 60).is_err());
        assert_eq!(MAX_OATH_SLOTS, MAX_CREDENTIALS);
    }

    #[test]
    fn oathslot_from_credential_preserva() {
        let c = OathCredential::new(lbl("TestService:alice"), vec![1, 2, 3], OathAlgorithm::Sha256, 7, OathType::Hotp, 41, false);
        let s = OathSlot::from_credential(&c).unwrap();
        assert_eq!(s.label, "TestService:alice");
        assert_eq!(s.hmac, OathAlgorithm::Sha256);
        assert_eq!(s.tipo, OathType::Hotp);
        assert_eq!(s.contador, 41);
        assert_eq!(s.digits, 7);
        assert_eq!(s.periodo, OATH_PERIOD_SECS);
    }
    fn put_totp(label: &str, secret: &[u8]) -> Vec<u8> {
        let mut t = Vec::new();
        write_tlv(&mut t, TAG_NAME, label.as_bytes());
        let mut kv = vec![0x21, 0x06];
        kv.extend_from_slice(secret);
        write_tlv(&mut t, TAG_KEY, &kv);
        t
    }

    fn put_hotp(label: &str, secret: &[u8], counter: u32) -> Vec<u8> {
        let mut t = Vec::new();
        write_tlv(&mut t, TAG_NAME, label.as_bytes());
        let mut kv = vec![0x11, 0x06];
        kv.extend_from_slice(secret);
        write_tlv(&mut t, TAG_KEY, &kv);
        write_tlv(&mut t, TAG_IMF, &counter.to_be_bytes());
        t
    }

    fn name_only(label: &str) -> Vec<u8> {
        let mut t = Vec::new();
        write_tlv(&mut t, TAG_NAME, label.as_bytes());
        t
    }

    fn code_totp(label: &str, challenge: &[u8]) -> Vec<u8> {
        let mut t = Vec::new();
        write_tlv(&mut t, TAG_NAME, label.as_bytes());
        write_tlv(&mut t, TAG_CHALLENGE, challenge);
        t
    }

    #[test]
    fn device_gates_fase6() {
        let mut ap = OathApplet::new();
        let put = put_totp("A:a", b"12345678901234567890");
        assert_eq!(ap.device_put(&put, true, false), Err(OathDeviceError::NeedUp));
        assert_eq!(ap.device_put(&put, false, true), Err(OathDeviceError::NeedPin));
        assert_eq!(ap.device_list(false, false), Err(OathDeviceError::NeedUp));
        assert_eq!(ap.device_code(&name_only("A:a"), false, false), Err(OathDeviceError::NeedUp));
        assert_eq!(ap.device_delete(&name_only("A:a"), false, true), Err(OathDeviceError::NeedPin));
        assert_eq!(ap.device_delete(&name_only("A:a"), true, false), Err(OathDeviceError::NeedUp));
        assert_eq!(OathDeviceError::NeedUp.code(), 0x01);
        assert_eq!(OathDeviceError::NeedPin.code(), 0x02);
        assert_eq!(OathDeviceError::NoSlot.code(), 0x03);
        assert_eq!(OathDeviceError::BadEnvelope.code(), 0x04);
    }

    #[test]
    fn device_put_list_code_delete_roundtrip() {
        let mut ap = OathApplet::new();
        ap.device_put(&put_totp("TestService:alice", b"12345678901234567890"), true, true).unwrap();
        let slots = ap.device_list(false, true).unwrap();
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].label, "TestService:alice");
        assert_eq!(slots[0].digits, 6);
        let r = ap.device_code(&code_totp("TestService:alice", &1u64.to_be_bytes()), false, true).unwrap();
        assert_eq!(r.code, "287082");
        assert_eq!(r.digits, 6);
        ap.device_delete(&name_only("TestService:alice"), true, true).unwrap();
        assert!(ap.device_list(false, true).unwrap().is_empty());
        assert_eq!(ap.device_code(&code_totp("TestService:alice", &1u64.to_be_bytes()), false, true), Err(OathDeviceError::NoSlot));
    }

    #[test]
    fn rfc4226_hotp_via_device_x10() {
        let mut ap = OathApplet::new();
        let secret = b"12345678901234567890";
        ap.device_put(&put_hotp("HOTP:alice", secret, 0), true, true).unwrap();
        let expected = [755224u32, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489];
        for (i, exp) in expected.iter().enumerate() {
            let r = ap.device_code(&name_only("HOTP:alice"), false, true).unwrap();
            let want = alloc::format!("{:06}", exp);
            assert_eq!(r.code, want, "HOTP mismatch at counter {}", i);
        }
        let slots = ap.device_list(false, true).unwrap();
        assert_eq!(slots[0].contador, 10);
    }

    #[test]
    fn rfc6238_totp_via_device() {
        let mut ap = OathApplet::new();
        let s256 = b"12345678901234567890123456789012";
        let mut t = Vec::new();
        write_tlv(&mut t, TAG_NAME, b"TOTP256:alice");
        let mut kv = vec![0x22, 0x08];
        kv.extend_from_slice(s256);
        write_tlv(&mut t, TAG_KEY, &kv);
        ap.device_put(&t, true, true).unwrap();
        let r = ap.device_code(&code_totp("TOTP256:alice", &1u64.to_be_bytes()), false, true).unwrap();
        assert_eq!(r.code, "46119246");
        assert_eq!(r.digits, 8);
        let s512 = b"1234567890123456789012345678901234567890123456789012345678901234";
        let mut t2 = Vec::new();
        write_tlv(&mut t2, TAG_NAME, b"TOTP512:alice");
        let mut kv2 = vec![0x23, 0x08];
        kv2.extend_from_slice(s512);
        write_tlv(&mut t2, TAG_KEY, &kv2);
        ap.device_put(&t2, true, true).unwrap();
        let r2 = ap.device_code(&code_totp("TOTP512:alice", &1u64.to_be_bytes()), false, true).unwrap();
        assert_eq!(r2.code, "90693936");
    }

    #[test]
    fn device_rejects_bad_envelope() {
        let mut ap = OathApplet::new();
        ap.device_put(&put_totp("B:b", b"12345678901234567890"), true, true).unwrap();
        assert_eq!(ap.device_put(b"not-tlv-at-all\xff", true, true), Err(OathDeviceError::BadEnvelope));
        assert_eq!(ap.device_put(&name_only(""), true, true), Err(OathDeviceError::BadEnvelope));
        let big = String::from_utf8(vec![b'x'; MAX_OATH_LABEL_BYTES + 1]).unwrap();
        assert_eq!(ap.device_put(&name_only(&big), true, true), Err(OathDeviceError::BadEnvelope));
        assert_eq!(ap.device_code(&code_totp("B:b", b"short"), false, true), Err(OathDeviceError::BadEnvelope));
        assert_eq!(ap.device_code(&name_only("B:b"), false, true), Err(OathDeviceError::BadEnvelope));
        let mut bad_digits = Vec::new();
        write_tlv(&mut bad_digits, TAG_NAME, b"C:c");
        write_tlv(&mut bad_digits, TAG_KEY, &[0x21, 0x05, 0xAA]);
        assert_eq!(ap.device_put(&bad_digits, true, true), Err(OathDeviceError::BadEnvelope));
        let mut oversize = vec![0x71u8; OATH_TLV_MAX_BYTES + 1];
        let _ = &mut oversize;
        assert_eq!(ap.device_put(&oversize, true, true), Err(OathDeviceError::BadEnvelope));
        assert_eq!(ap.device_code(&oversize, false, true), Err(OathDeviceError::BadEnvelope));
    }

    #[test]
    fn device_no_leak_list_code() {
        let mut ap = OathApplet::new();
        let secret = b"12345678901234567890";
        ap.device_put(&put_totp("GitHub:alice", secret), true, true).unwrap();
        let slots = ap.device_list(false, true).unwrap();
        let dbg = alloc::format!("{:?}", slots);
        assert!(!dbg.as_bytes().windows(secret.len()).any(|w| w == secret));
        let r = ap.device_code(&code_totp("GitHub:alice", &1u64.to_be_bytes()), false, true).unwrap();
        assert!(!r.code.as_bytes().windows(secret.len()).any(|w| w == secret));
        assert_eq!(r.code.len(), 6);
    }

    #[test]
    fn device_delete_wipes() {
        let mut ap = OathApplet::new();
        ap.device_put(&put_totp("Del:me", b"12345678901234567890"), true, true).unwrap();
        ap.device_delete(&name_only("Del:me"), true, true).unwrap();
        assert!(ap.device_list(false, true).unwrap().is_empty());
        assert_eq!(ap.device_delete(&name_only("Del:me"), true, true), Err(OathDeviceError::NoSlot));
        assert_eq!(ap.device_code(&code_totp("Del:me", &1u64.to_be_bytes()), false, true), Err(OathDeviceError::NoSlot));
    }

    #[test]
    fn device_65th_is_noslot() {
        let mut ap = OathApplet::new();
        for i in 0..MAX_CREDENTIALS {
            let label = alloc::format!("L{}:u", i);
            ap.device_put(&put_totp(&label, b"12345678901234567890"), true, true).unwrap();
        }
        assert_eq!(ap.device_list(false, true).unwrap().len(), MAX_CREDENTIALS);
        assert_eq!(ap.device_put(&put_totp("Extra:u", b"12345678901234567890"), true, true), Err(OathDeviceError::NoSlot));
    }

    #[test]
    fn hotp_journal_monotonico() {
        let mut ap = OathApplet::new();
        ap.device_put(&put_hotp("J:a", b"12345678901234567890", 0), true, true).unwrap();
        ap.device_code(&name_only("J:a"), false, true).unwrap();
        ap.device_code(&name_only("J:a"), false, true).unwrap();
        let blob = ap.export_hotp_counts();
        let mut ap2 = OathApplet::new();
        ap2.device_put(&put_hotp("J:a", b"12345678901234567890", 0), true, true).unwrap();
        ap2.import_hotp_counts(&blob).unwrap();
        assert_eq!(ap2.device_list(false, true).unwrap()[0].contador, 2);
        let low = ap2.export_hotp_counts();
        ap.import_hotp_counts(&low).unwrap();
        assert_eq!(ap.device_list(false, true).unwrap()[0].contador, 2);
        let mut bad = blob.clone();
        bad[0] ^= 0xFF;
        assert_eq!(ap2.import_hotp_counts(&bad), Err(OathDeviceError::BadEnvelope));
        assert_eq!(ap2.import_hotp_counts(b"short"), Err(OathDeviceError::BadEnvelope));
    }

    #[test]
    fn code_zero_pad_width() {
        let mut ap = OathApplet::new();
        let mut t = Vec::new();
        write_tlv(&mut t, TAG_NAME, b"Pad:alice");
        let mut kv = vec![0x21, 0x08];
        kv.extend_from_slice(b"12345678901234567890");
        write_tlv(&mut t, TAG_KEY, &kv);
        ap.device_put(&t, true, true).unwrap();
        let r = ap.device_code(&code_totp("Pad:alice", &1u64.to_be_bytes()), false, true).unwrap();
        assert_eq!(r.code.len(), 8);
        assert_eq!(r.code, "94287082");
        assert_eq!(alloc::format!("{:0>width$}", 287082u32, width = 8), "00287082");
    }}