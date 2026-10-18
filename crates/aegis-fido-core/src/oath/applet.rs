extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;
use rand_core::RngCore;

use super::crypto::{calculate_code, calculate_code_from_challenge, pbkdf2_sha1, verify_challenge_response};
use super::presence::PresenceVerifier;
use super::tlv::{find_tlv, parse_tlv_records, write_tlv};
use super::types::*;

/// Version reported by the AegisKey OATH applet (YKOATH v5.4.3 compatible)
pub const APPLET_VERSION: [u8; 3] = [0x05, 0x04, 0x03];

/// Maximum number of OATH credentials stored in device
pub const MAX_CREDENTIALS: usize = 64;

/// AegisKey YKOATH Applet implementation
pub struct OathApplet {
    pub credentials: Vec<OathCredential>,
    pub salt: [u8; 8],
    pub has_password: bool,
    pub key: [u8; 16],
    pub authenticated: bool,
    pub current_challenge: [u8; 8],
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
