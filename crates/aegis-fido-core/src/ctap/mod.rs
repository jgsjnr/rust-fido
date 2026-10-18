pub mod cbor;
pub mod client_pin;
pub mod config;
pub mod cred_mgmt;
pub mod get_assertion;
pub mod info;
pub mod large_blobs;
pub mod make_cred;
pub mod reset;
pub mod status_code;

use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};

use crate::credential::non_resident::CredentialWrapper;
use crate::credential::store::{CredentialStore, MemoryCredentialStore};
use crate::ctap::client_pin::{ClientPinHandler, ClientPinState};
use crate::ctap::config::ConfigHandler;
use crate::ctap::cred_mgmt::{CredentialManagementHandler, CredentialManagementState};
use crate::ctap::get_assertion::{GetAssertionHandler, GetAssertionState};
use crate::ctap::info::{AuthenticatorInfo, AuthenticatorInfoConfig};
use crate::ctap::large_blobs::{LargeBlobsHandler, LargeBlobsStorage};
use crate::ctap::make_cred::MakeCredentialHandler;
use crate::ctap::reset::ResetHandler;
use crate::ctap::status_code::{CtapError, CTAP1_ERR_SUCCESS};

pub const CTAP_CMD_MAKE_CREDENTIAL: u8 = 0x01;
pub const CTAP_CMD_GET_ASSERTION: u8 = 0x02;
pub const CTAP_CMD_GET_INFO: u8 = 0x04;
pub const CTAP_CMD_CLIENT_PIN: u8 = 0x06;
pub const CTAP_CMD_RESET: u8 = 0x07;
pub const CTAP_CMD_GET_NEXT_ASSERTION: u8 = 0x08;
pub const CTAP_CMD_CREDENTIAL_MANAGEMENT: u8 = 0x0A;
pub const CTAP_CMD_LARGE_BLOBS: u8 = 0x0C;
pub const CTAP_CMD_CONFIG: u8 = 0x0D;

pub struct CtapEngine<S: CredentialStore = MemoryCredentialStore> {
    pub store: S,
    pub wrapper: CredentialWrapper,
    pub pin_state: ClientPinState,
    pub info_config: AuthenticatorInfoConfig,
    pub assertion_state: GetAssertionState,
    pub cred_mgmt_state: CredentialManagementState,
    pub large_blobs: LargeBlobsStorage,
    pub boot_timestamp_seconds: u64,
    pub user_presence_confirmed: bool,
    pub rk_deny_policy: bool,
}

impl CtapEngine<MemoryCredentialStore> {
    pub fn new(master_key: [u8; 32], boot_time_seconds: u64) -> Self {
        Self {
            store: MemoryCredentialStore::new(50),
            wrapper: CredentialWrapper::new(master_key),
            pin_state: ClientPinState::default(),
            info_config: AuthenticatorInfoConfig::default(),
            assertion_state: GetAssertionState::default(),
            cred_mgmt_state: CredentialManagementState::default(),
            large_blobs: LargeBlobsStorage::new(),
            boot_timestamp_seconds: boot_time_seconds,
            user_presence_confirmed: true, // defaults to confirmed in unit tests, configurable
            rk_deny_policy: false,
        }
    }
}

impl<S: CredentialStore> CtapEngine<S> {
    pub fn set_user_presence(&mut self, confirmed: bool) {
        self.user_presence_confirmed = confirmed;
    }

    pub fn set_rk_deny_policy(&mut self, deny: bool) {
        self.rk_deny_policy = deny;
    }

    /// Processes a single raw CTAP2 command packet [cmd_byte, cbor_payload...]
    /// Returns [status_code, response_cbor...]
    pub fn process_packet<R: RngCore + CryptoRng>(
        &mut self,
        packet: &[u8],
        current_time_seconds: u64,
        rng: &mut R,
    ) -> Vec<u8> {
        if packet.is_empty() {
            return vec![CtapError::InvalidLength.to_status_code()];
        }

        let cmd = packet[0];
        let payload = &packet[1..];

        match self.process_command(cmd, payload, current_time_seconds, rng) {
            Ok(res_bytes) => {
                let mut out = Vec::with_capacity(1 + res_bytes.len());
                out.push(CTAP1_ERR_SUCCESS);
                out.extend_from_slice(&res_bytes);
                out
            }
            Err(err) => vec![err.to_status_code()],
        }
    }

    /// Dispatches a CTAP2 command byte and CBOR payload
    pub fn process_command<R: RngCore + CryptoRng>(
        &mut self,
        cmd: u8,
        payload: &[u8],
        current_time_seconds: u64,
        rng: &mut R,
    ) -> Result<Vec<u8>, CtapError> {
        self.info_config.pin_set = self.pin_state.is_pin_set();
        self.info_config.min_pin_length = self.pin_state.min_pin_length;
        self.info_config.remaining_resident_credentials = self
            .store
            .max_resident()
            .saturating_sub(self.store.count_resident());

        match cmd {
            CTAP_CMD_GET_INFO => AuthenticatorInfo::handle_get_info(&self.info_config),
            CTAP_CMD_MAKE_CREDENTIAL => MakeCredentialHandler::handle(
                &mut self.store,
                &self.wrapper,
                &mut self.pin_state,
                &self.info_config,
                self.user_presence_confirmed,
                self.rk_deny_policy,
                payload,
                rng,
            ),
            CTAP_CMD_GET_ASSERTION => GetAssertionHandler::handle(
                &mut self.store,
                &self.wrapper,
                &mut self.pin_state,
                &mut self.assertion_state,
                self.user_presence_confirmed,
                payload,
                rng,
            ),
            CTAP_CMD_GET_NEXT_ASSERTION => {
                GetAssertionHandler::handle_next(&mut self.store, &mut self.assertion_state, rng)
            }
            CTAP_CMD_CLIENT_PIN => ClientPinHandler::handle(&mut self.pin_state, payload, rng),
            CTAP_CMD_RESET => {
                let res = ResetHandler::handle(
                    self.boot_timestamp_seconds,
                    current_time_seconds,
                    self.user_presence_confirmed,
                )?;
                // Reset state
                self.pin_state = ClientPinState::default();
                self.large_blobs.clear();
                let mut new_master = [0u8; 32];
                rng.fill_bytes(&mut new_master);
                self.wrapper = CredentialWrapper::new(new_master);
                Ok(res)
            }
            CTAP_CMD_CREDENTIAL_MANAGEMENT => CredentialManagementHandler::handle(
                &mut self.store,
                &mut self.cred_mgmt_state,
                &self.pin_state,
                payload,
            ),
            CTAP_CMD_LARGE_BLOBS => {
                LargeBlobsHandler::handle(&mut self.large_blobs, &self.pin_state, payload)
            }
            CTAP_CMD_CONFIG => {
                ConfigHandler::handle(&mut self.info_config, &self.pin_state, payload)
            }
            _ => Err(CtapError::InvalidCommand),
        }
    }
}
