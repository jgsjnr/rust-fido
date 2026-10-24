//! T-FD-01 maquina de estados CTAP normativa (GEN-DEVICE).
//!
//! Motivo: o transporte (`ctaphid`/`serial_ctaphid`) entrega bytes sem
//! decidir nada; sem um gate normativo previo o device aceitaria comando
//! desconhecido, mensagem gigante, PIN fraco/bloqueado ou operacao sem UP
//! vinculado (secao 9: erros normativos + limites + PIN/bloqueio + UP).
//!
//! - Comandos: tabela `CtapCommand` (0x01/0x02/0x04/0x06/0x07/0x08/0x0A/0x0C/0x0D);
//!   byte fora da tabela responde `InvalidCommand` (CTAP 0x01).
//! - Limites: quadro vazio e `InvalidLength`; total acima de
//!   `CTAP_MAX_MSG_LEN` (7609 B, identico ao CTAPHID) e `LimitExceeded`;
//!   PIN fora de 4..=63 e `PinPolicyViolation`.
//! - PIN/UV: contadores com trava (`PinBlocked`/`UvBlocked` grudam ate
//!   `factory_reset`, nunca voltam no power-cycle); segredo nunca guardado
//!   aqui, so presenca do `pinUvAuthToken` (`token_live`).
//! - Sobre T-CR-01/T-CR-06: acordo de chaves delega a `P256Backend::ecdh`
//!   (`pin_key_agreement`) e o token nasce de `HrngSource::fill`
//!   (`issue_token`); sem acordo/token o gate nega fail-closed.
//! - UP vinculado: `check_up` exige grant de `UpPolicy` para a mesma
//!   `OperationHash` (confused deputy negado com `OperationDenied`).
//! - Sem mock falso: teste usa Xorshift deterministico SOMENTE como fixture
//!   de RNG/clock; a curva real e exercida via `SoftwareP256`/`EspP256`.
//! - `no_std` compativel: so `core`; `Debug` nunca expoe segredo.
//!
//! Wire codes: CTAP 2.1 secao 6.3 (canonicos). Onde o nucleo legado usa
//! apelidos colidentes, este modulo mantem o canonico e documenta.

use core::fmt;

use crate::crypto_hrng::{HrngError, HrngSource};
use crate::crypto_p256::P256Backend;
use crate::up_policy::{OperationHash, UpDeny, UpGrant, UpPolicy};

/// Teto CTAP/CTAPHID: `57 + 128 * 59` B (identico ao transporte USB/serial).
pub const CTAP_MAX_MSG_LEN: usize = 7609;
/// Minimo: 1 byte de comando.
pub const CTAP_MIN_MSG_LEN: usize = 1;
/// PIN UTF-8: minimo normativo ( authenticator `minPinLength` >= 4 ).
pub const PIN_MIN_LEN: usize = 4;
/// PIN UTF-8: teto normativo (63 bytes + terminador).
pub const PIN_MAX_LEN: usize = 63;
/// Tentativas de PIN por power-cycle (CTAP: 8, trava em 0).
pub const PIN_MAX_RETRIES: u8 = 8;
/// Tentativas de UV nativa (CTAP: 3, trava em 0).
pub const UV_MAX_RETRIES: u8 = 3;
/// Tamanho do `pinUvAuthToken`.
pub const PIN_TOKEN_BYTES: usize = 32;

/// Comandos CTAP2 admitidos pelo gate (antes do dispatch CBOR de T-FD-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtapCommand {
    MakeCredential,
    GetAssertion,
    GetInfo,
    ClientPin,
    Reset,
    GetNextAssertion,
    CredentialManagement,
    LargeBlobs,
    AuthenticatorConfig,
}

impl CtapCommand {
    /// Decodifica o byte de comando; desconhecido vira `InvalidCommand`.
    pub fn from_u8(cmd: u8) -> Result<Self, CtapError> {
        match cmd {
            0x01 => Ok(Self::MakeCredential),
            0x02 => Ok(Self::GetAssertion),
            0x04 => Ok(Self::GetInfo),
            0x06 => Ok(Self::ClientPin),
            0x07 => Ok(Self::Reset),
            0x08 => Ok(Self::GetNextAssertion),
            0x0A => Ok(Self::CredentialManagement),
            0x0C => Ok(Self::LargeBlobs),
            0x0D => Ok(Self::AuthenticatorConfig),
            _ => Err(CtapError::InvalidCommand),
        }
    }

    /// Byte canonico do comando.
    pub fn code(self) -> u8 {
        match self {
            Self::MakeCredential => 0x01,
            Self::GetAssertion => 0x02,
            Self::GetInfo => 0x04,
            Self::ClientPin => 0x06,
            Self::Reset => 0x07,
            Self::GetNextAssertion => 0x08,
            Self::CredentialManagement => 0x0A,
            Self::LargeBlobs => 0x0C,
            Self::AuthenticatorConfig => 0x0D,
        }
    }

    /// `true` quando a operacao sempre exige toque fisico (UP vinculado).
    pub fn requires_up(self) -> bool {
        match self {
            Self::MakeCredential | Self::GetAssertion | Self::Reset => true,
            Self::GetInfo
            | Self::ClientPin
            | Self::GetNextAssertion
            | Self::CredentialManagement
            | Self::LargeBlobs
            | Self::AuthenticatorConfig => false,
        }
    }
}
/// Erro CTAP normativo com wire value CTAP 2.1 secao 6.3.
///
/// Nenhuma variante carrega material secreto (so contadores/flags vivem
/// no gate; PIN/token nunca sao armazenados nem formatados).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CtapError {
    Success,
    InvalidCommand,
    InvalidParameter,
    InvalidLength,
    InvalidSeq,
    Timeout,
    ChannelBusy,
    LockRequired,
    InvalidChannel,
    CborUnexpectedType,
    InvalidCbor,
    MissingParameter,
    LimitExceeded,
    UnsupportedExtension,
    CredentialExcluded,
    Processing,
    InvalidCredential,
    UserActionPending,
    OperationPending,
    NoOperations,
    UnsupportedAlgorithm,
    OperationDenied,
    KeyStoreFull,
    UnsupportedOption,
    InvalidOption,
    KeepaliveCancel,
    NoCredentials,
    UserActionTimeout,
    NotAllowed,
    PinInvalid,
    PinBlocked,
    PinAuthInvalid,
    PinAuthBlocked,
    PinNotSet,
    PinRequired,
    PinPolicyViolation,
    PinTokenExpired,
    RequestTooLarge,
    ActionTimeout,
    UpRequired,
    UvBlocked,
    IntegrityFailure,
    InvalidSubcommand,
    UvInvalid,
    UnauthorizedPermission,
}

impl CtapError {
    /// Wire value normativo (u8 respondido ao host).
    pub fn code(self) -> u8 {
        match self {
            Self::Success => 0x00,
            Self::InvalidCommand => 0x01,
            Self::InvalidParameter => 0x02,
            Self::InvalidLength => 0x03,
            Self::InvalidSeq => 0x04,
            Self::Timeout => 0x05,
            Self::ChannelBusy => 0x06,
            Self::LockRequired => 0x0A,
            Self::InvalidChannel => 0x0B,
            Self::CborUnexpectedType => 0x11,
            Self::InvalidCbor => 0x12,
            Self::MissingParameter => 0x14,
            Self::LimitExceeded => 0x15,
            Self::UnsupportedExtension => 0x16,
            Self::CredentialExcluded => 0x19,
            Self::Processing => 0x21,
            Self::InvalidCredential => 0x22,
            Self::UserActionPending => 0x23,
            Self::OperationPending => 0x24,
            Self::NoOperations => 0x25,
            Self::UnsupportedAlgorithm => 0x26,
            Self::OperationDenied => 0x27,
            Self::KeyStoreFull => 0x28,
            Self::UnsupportedOption => 0x2B,
            Self::InvalidOption => 0x2C,
            Self::KeepaliveCancel => 0x2D,
            Self::NoCredentials => 0x2E,
            Self::UserActionTimeout => 0x2F,
            Self::NotAllowed => 0x30,
            Self::PinInvalid => 0x31,
            Self::PinBlocked => 0x32,
            Self::PinAuthInvalid => 0x33,
            Self::PinAuthBlocked => 0x34,
            Self::PinNotSet => 0x35,
            Self::PinRequired => 0x36,
            Self::PinPolicyViolation => 0x37,
            Self::PinTokenExpired => 0x38,
            Self::RequestTooLarge => 0x39,
            Self::ActionTimeout => 0x3A,
            Self::UpRequired => 0x3B,
            Self::UvBlocked => 0x3C,
            Self::IntegrityFailure => 0x3D,
            Self::InvalidSubcommand => 0x3E,
            Self::UvInvalid => 0x3F,
            Self::UnauthorizedPermission => 0x40,
        }
    }

    /// Nome estavel para log/diagnostico (sem segredo, so o motivo).
    pub fn name(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::InvalidCommand => "invalid_command",
            Self::InvalidParameter => "invalid_parameter",
            Self::InvalidLength => "invalid_length",
            Self::InvalidSeq => "invalid_seq",
            Self::Timeout => "timeout",
            Self::ChannelBusy => "channel_busy",
            Self::LockRequired => "lock_required",
            Self::InvalidChannel => "invalid_channel",
            Self::CborUnexpectedType => "cbor_unexpected_type",
            Self::InvalidCbor => "invalid_cbor",
            Self::MissingParameter => "missing_parameter",
            Self::LimitExceeded => "limit_exceeded",
            Self::UnsupportedExtension => "unsupported_extension",
            Self::CredentialExcluded => "credential_excluded",
            Self::Processing => "processing",
            Self::InvalidCredential => "invalid_credential",
            Self::UserActionPending => "user_action_pending",
            Self::OperationPending => "operation_pending",
            Self::NoOperations => "no_operations",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::OperationDenied => "operation_denied",
            Self::KeyStoreFull => "key_store_full",
            Self::UnsupportedOption => "unsupported_option",
            Self::InvalidOption => "invalid_option",
            Self::KeepaliveCancel => "keepalive_cancel",
            Self::NoCredentials => "no_credentials",
            Self::UserActionTimeout => "user_action_timeout",
            Self::NotAllowed => "not_allowed",
            Self::PinInvalid => "pin_invalid",
            Self::PinBlocked => "pin_blocked",
            Self::PinAuthInvalid => "pin_auth_invalid",
            Self::PinAuthBlocked => "pin_auth_blocked",
            Self::PinNotSet => "pin_not_set",
            Self::PinRequired => "pin_required",
            Self::PinPolicyViolation => "pin_policy_violation",
            Self::PinTokenExpired => "pin_token_expired",
            Self::RequestTooLarge => "request_too_large",
            Self::ActionTimeout => "action_timeout",
            Self::UpRequired => "up_required",
            Self::UvBlocked => "uv_blocked",
            Self::IntegrityFailure => "integrity_failure",
            Self::InvalidSubcommand => "invalid_subcommand",
            Self::UvInvalid => "uv_invalid",
            Self::UnauthorizedPermission => "unauthorized_permission",
        }
    }
}

impl fmt::Debug for CtapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CtapError({} 0x{:02X})", self.name(), self.code())
    }
}

/// Relogio monotonico em ms (HW via trait; board injeta `esp_timer`).
pub trait CtapClock {
    fn now_ms(&self) -> u64;
}

/// Gate de admissao CTAP: valida comando, tamanho, PIN/UV e UP antes do
/// dispatch CBOR (T-FD-04). Nao guarda PIN nem token, so contadores e
/// flags; por isso o `Debug` e seguro por construcao.
pub struct PinUvGate {
    pin_set: bool,
    pin_retries: u8,
    uv_retries: u8,
    key_agreement: bool,
    token_live: bool,
}

impl PinUvGate {
    /// Cria o gate; `pin_set` reflete o armazenamento persistente.
    pub fn new(pin_set: bool) -> Self {
        Self {
            pin_set,
            pin_retries: PIN_MAX_RETRIES,
            uv_retries: UV_MAX_RETRIES,
            key_agreement: false,
            token_live: false,
        }
    }

    /// Marca que o ECDH ClientPIN (T-CR-01) foi concluido neste canal.
    pub fn set_key_agreement(&mut self, established: bool) {
        self.key_agreement = established;
        if !established {
            self.token_live = false;
        }
    }

    /// `true` quando o acordo ECDH previo existe (ClientPIN set/change/token).
    pub fn has_key_agreement(&self) -> bool {
        self.key_agreement
    }

    /// `true` quando ha PIN cadastrado.
    pub fn is_pin_set(&self) -> bool {
        self.pin_set
    }

    /// `true` quando o PIN travou (retries == 0; so `factory_reset` destrava).
    pub fn is_pin_blocked(&self) -> bool {
        self.pin_retries == 0
    }

    /// `true` quando a UV nativa travou (so `factory_reset` destrava).
    pub fn is_uv_blocked(&self) -> bool {
        self.uv_retries == 0
    }

    /// Tentativas restantes de PIN (resposta `getPinRetries`, sem segredo).
    pub fn pin_retries(&self) -> u8 {
        self.pin_retries
    }

    /// Tentativas restantes de UV (resposta `getUvRetries`, sem segredo).
    pub fn uv_retries(&self) -> u8 {
        self.uv_retries
    }

    /// Valida cabecalho CTAP: comando conhecido + tamanho dentro do teto.
    ///
    /// `total_len` inclui o byte de comando. Vazio e `InvalidLength`;
    /// acima de 7609 B e `LimitExceeded` (fail-closed, sem truncar).
    pub fn check_request(&self, cmd: u8, total_len: usize) -> Result<CtapCommand, CtapError> {
        if total_len < CTAP_MIN_MSG_LEN {
            return Err(CtapError::InvalidLength);
        }
        if total_len > CTAP_MAX_MSG_LEN {
            return Err(CtapError::LimitExceeded);
        }
        CtapCommand::from_u8(cmd)
    }

    /// Valida comprimento do PIN em bytes UTF-8 (4..=63).
    pub fn check_pin_length(&self, len: usize) -> Result<(), CtapError> {
        if !(PIN_MIN_LEN..=PIN_MAX_LEN).contains(&len) {
            return Err(CtapError::PinPolicyViolation);
        }
        Ok(())
    }

    /// Registra falha de PIN; trava em 0 e responde `PinBlocked`.
    pub fn record_pin_failure(&mut self) -> CtapError {
        self.pin_retries = self.pin_retries.saturating_sub(1);
        self.token_live = false;
        if self.is_pin_blocked() {
            CtapError::PinBlocked
        } else {
            CtapError::PinInvalid
        }
    }

    /// Registra falha de UV nativa; trava em 0 e responde `UvBlocked`.
    pub fn record_uv_failure(&mut self) -> CtapError {
        self.uv_retries = self.uv_retries.saturating_sub(1);
        if self.is_uv_blocked() {
            CtapError::UvBlocked
        } else {
            CtapError::UvInvalid
        }
    }

    /// PIN verificado com sucesso: restaura retries e derruba bloqueio logico.
    ///
    /// Nao recria PIN nem token; o chamador emite novo token via
    /// `issue_token` (T-CR-06) apos este reset de contador.
    pub fn on_pin_verified(&mut self) {
        self.pin_retries = PIN_MAX_RETRIES;
    }
    /// Emite o `pinUvAuthToken` (32 B via T-CR-06) apos PIN verificado.
    ///
    /// Exige PIN cadastrado, nao bloqueado e acordo ECDH previo; qualquer
    /// falha do HRNG nega fail-closed (`IntegrityFailure`/`OperationDenied`).
    /// O token e escrito em `out` (cofre do chamador), aqui fica so a flag.
    pub fn issue_token<S: HrngSource>(
        &mut self,
        rng: &mut S,
        out: &mut [u8; PIN_TOKEN_BYTES],
    ) -> Result<(), CtapError> {
        if !self.pin_set {
            return Err(CtapError::PinNotSet);
        }
        if self.is_pin_blocked() {
            return Err(CtapError::PinBlocked);
        }
        if !self.key_agreement {
            return Err(CtapError::PinAuthInvalid);
        }
        rng.fill(out).map_err(|e| match e {
            HrngError::StuckSample | HrngError::BiasedSample => CtapError::IntegrityFailure,
            HrngError::TooShort | HrngError::TooLarge => CtapError::LimitExceeded,
            HrngError::NotSeeded | HrngError::Unsupported => CtapError::OperationDenied,
        })?;
        self.token_live = true;
        Ok(())
    }

    /// Verifica sessao `pinUvAuth` viva (sem consumir; expira no power-cycle).
    pub fn verify_token(&self) -> Result<(), CtapError> {
        if self.token_live {
            Ok(())
        } else {
            Err(CtapError::PinTokenExpired)
        }
    }

    /// Invalida a sessao (power-cycle, reset ou troca de acordo ECDH).
    pub fn invalidate_token(&mut self) {
        self.token_live = false;
    }

    /// Power-cycle: derruba sessao e acordo, mas MANTEM trava de PIN/UV.
    ///
    /// Trava so sai com `factory_reset` (CTAP Reset com UP), conforme secao 9.
    pub fn power_cycle(&mut self) {
        self.key_agreement = false;
        self.token_live = false;
    }

    /// Reset de fabrica (apos UP + janela): limpa PIN, destrava e derruba tudo.
    pub fn factory_reset(&mut self) {
        self.pin_set = false;
        self.pin_retries = PIN_MAX_RETRIES;
        self.uv_retries = UV_MAX_RETRIES;
        self.key_agreement = false;
        self.token_live = false;
    }

    /// Marca PIN como cadastrado (apos `setPIN` com acordo + politica ok).
    pub fn set_pin_registered(&mut self) {
        self.pin_set = true;
        self.pin_retries = PIN_MAX_RETRIES;
    }

    /// Autoriza operacao com UP vinculado a `op` via `UpPolicy`.
    ///
    /// Mapeia `UpDeny` para o vocabulario CTAP sem vazar detalhe interno:
    /// toque errado/replay/expirado nega a operacao; timeout/cancelamento
    /// viram os erros de acao correspondentes; falha de HW vira integridade.
    pub fn check_up(
        &self,
        policy: &UpPolicy,
        grant: &mut UpGrant,
        op: OperationHash,
        now_ms: u64,
    ) -> Result<(), CtapError> {
        policy.authorize(grant, op, now_ms).map_err(|e| match e {
            UpDeny::WrongOperation | UpDeny::Replayed | UpDeny::Expired => {
                CtapError::OperationDenied
            }
            UpDeny::Timeout => CtapError::UserActionTimeout,
            UpDeny::Cancelled => CtapError::KeepaliveCancel,
            UpDeny::HardwareFault => CtapError::IntegrityFailure,
            UpDeny::WindowTooLarge => CtapError::InvalidParameter,
        })
    }

    /// Regra de UV para MakeCredential/GetAssertion (CBOR ja decodificado em
    /// T-FD-04; aqui so o predicado fail-closed sobre flags ja apuradas).
    ///
    /// - UV bloqueada nega sempre (`UvBlocked`), mesmo com `up=true`.
    /// - `require_uv` sem `uv_performed` nem `pin_auth_ok` e `PinRequired`.
    /// - PIN exigido sem `pin_auth_ok` e `PinAuthInvalid`.
    pub fn check_uv_policy(
        &self,
        require_uv: bool,
        uv_performed: bool,
        pin_auth_ok: bool,
    ) -> Result<(), CtapError> {
        if self.is_uv_blocked() {
            return Err(CtapError::UvBlocked);
        }
        if require_uv && !uv_performed && !pin_auth_ok {
            return Err(CtapError::PinRequired);
        }
        Ok(())
    }
}

impl fmt::Debug for PinUvGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinUvGate")
            .field("pin_set", &self.pin_set)
            .field("pin_retries", &self.pin_retries)
            .field("uv_retries", &self.uv_retries)
            .field("key_agreement", &self.key_agreement)
            .field("token_live", &self.token_live)
            .finish()
    }
}

/// Acordo ECDH P-256 do ClientPIN sobre T-CR-01 (`P256Backend`).
///
/// Wrapper fino e auditavel: a curva real executa no backend; falha de
/// entrada vira `InvalidParameter` e ponto identidade/falha vira
/// `PinAuthInvalid` (sem segredo no erro, sem log de escalar).
pub fn pin_key_agreement<B: P256Backend>(
    secret: &[u8; 32],
    peer_sec1: &[u8],
) -> Result<[u8; 32], CtapError> {
    B::ecdh(secret, peer_sec1).map_err(|e| {
        use crate::crypto_p256::P256Error;
        match e {
            P256Error::InvalidSecret | P256Error::InvalidPublicKey => CtapError::InvalidParameter,
            P256Error::InvalidSignature | P256Error::IdentityPeer | P256Error::EcdhFailed => {
                CtapError::PinAuthInvalid
            }
        }
    })
}

/// Mapeia `HrngError` (T-CR-06) para CTAP sem expor amostra.
pub fn map_hrng_error(e: HrngError) -> CtapError {
    match e {
        HrngError::StuckSample | HrngError::BiasedSample => CtapError::IntegrityFailure,
        HrngError::TooShort | HrngError::TooLarge => CtapError::LimitExceeded,
        HrngError::NotSeeded | HrngError::Unsupported => CtapError::OperationDenied,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_hrng::HRNG_MAX_FILL;
    use crate::crypto_p256::{EspP256, SoftwareP256};

    /// Clock deterministico, SOMENTE fixture de tempo (nao simula HW cripto).
    struct TestClock(u64);
    impl CtapClock for TestClock {
        fn now_ms(&self) -> u64 {
            self.0
        }
    }

    /// RNG deterministico (xorshift), SOMENTE fixture; a curva real roda no backend.
    struct TestRng(u64);
    impl HrngSource for TestRng {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), HrngError> {
            if dest.is_empty() {
                return Err(HrngError::TooShort);
            }
            if dest.len() > HRNG_MAX_FILL {
                return Err(HrngError::TooLarge);
            }
            for chunk in dest.chunks_mut(8) {
                let mut x = self.0;
                if x == 0 {
                    x = 0x9E3779B97F4A7C15;
                }
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                let v = x.to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
            Ok(())
        }
    }

    fn op(byte: u8) -> OperationHash {
        OperationHash([byte; 32])
    }

    #[test]
    fn wire_codes_are_normative() {
        assert_eq!(CtapError::Success.code(), 0x00);
        assert_eq!(CtapError::InvalidCommand.code(), 0x01);
        assert_eq!(CtapError::InvalidParameter.code(), 0x02);
        assert_eq!(CtapError::InvalidLength.code(), 0x03);
        assert_eq!(CtapError::LockRequired.code(), 0x0A);
        assert_eq!(CtapError::InvalidChannel.code(), 0x0B);
        assert_eq!(CtapError::MissingParameter.code(), 0x14);
        assert_eq!(CtapError::LimitExceeded.code(), 0x15);
        assert_eq!(CtapError::NotAllowed.code(), 0x30);
        assert_eq!(CtapError::PinInvalid.code(), 0x31);
        assert_eq!(CtapError::PinBlocked.code(), 0x32);
        assert_eq!(CtapError::PinAuthInvalid.code(), 0x33);
        assert_eq!(CtapError::PinAuthBlocked.code(), 0x34);
        assert_eq!(CtapError::PinNotSet.code(), 0x35);
        assert_eq!(CtapError::PinRequired.code(), 0x36);
        assert_eq!(CtapError::PinPolicyViolation.code(), 0x37);
        assert_eq!(CtapError::PinTokenExpired.code(), 0x38);
        assert_eq!(CtapError::UpRequired.code(), 0x3B);
        assert_eq!(CtapError::UvBlocked.code(), 0x3C);
        assert_eq!(CtapError::UvInvalid.code(), 0x3F);
    }

    #[test]
    fn command_table_and_up_rule() {
        assert_eq!(
            CtapCommand::from_u8(0x01).unwrap(),
            CtapCommand::MakeCredential
        );
        assert_eq!(CtapCommand::from_u8(0x04).unwrap(), CtapCommand::GetInfo);
        assert_eq!(CtapCommand::from_u8(0x06).unwrap().code(), 0x06);
        assert_eq!(
            CtapCommand::from_u8(0xFF).unwrap_err(),
            CtapError::InvalidCommand
        );
        assert!(CtapCommand::MakeCredential.requires_up());
        assert!(CtapCommand::GetAssertion.requires_up());
        assert!(CtapCommand::Reset.requires_up());
        assert!(!CtapCommand::GetInfo.requires_up());
        assert!(!CtapCommand::ClientPin.requires_up());
    }

    #[test]
    fn request_limits_fail_closed() {
        let gate = PinUvGate::new(false);
        assert_eq!(
            gate.check_request(0x04, 0).unwrap_err(),
            CtapError::InvalidLength
        );
        assert_eq!(
            gate.check_request(0x04, CTAP_MAX_MSG_LEN + 1).unwrap_err(),
            CtapError::LimitExceeded
        );
        assert_eq!(
            gate.check_request(0xFF, 16).unwrap_err(),
            CtapError::InvalidCommand
        );
        assert_eq!(
            gate.check_request(0x04, CTAP_MAX_MSG_LEN).unwrap(),
            CtapCommand::GetInfo
        );
        let clock = TestClock(1_500);
        assert_eq!(clock.now_ms(), 1_500);
    }

    #[test]
    fn pin_length_policy() {
        let gate = PinUvGate::new(true);
        assert_eq!(
            gate.check_pin_length(3).unwrap_err(),
            CtapError::PinPolicyViolation
        );
        gate.check_pin_length(4).expect("minimo ok");
        gate.check_pin_length(63).expect("teto ok");
        assert_eq!(
            gate.check_pin_length(64).unwrap_err(),
            CtapError::PinPolicyViolation
        );
    }

    #[test]
    fn pin_retries_lock_and_factory_reset() {
        let mut gate = PinUvGate::new(true);
        for _ in 0..PIN_MAX_RETRIES - 1 {
            assert_eq!(gate.record_pin_failure(), CtapError::PinInvalid);
        }
        assert_eq!(gate.record_pin_failure(), CtapError::PinBlocked);
        assert!(gate.is_pin_blocked());
        gate.power_cycle();
        assert!(gate.is_pin_blocked());
        let mut token = [0u8; PIN_TOKEN_BYTES];
        let mut rng = TestRng(0x1234);
        gate.set_key_agreement(true);
        assert_eq!(
            gate.issue_token(&mut rng, &mut token).unwrap_err(),
            CtapError::PinBlocked
        );
        gate.factory_reset();
        assert!(!gate.is_pin_blocked());
        assert!(!gate.is_pin_set());
    }

    #[test]
    fn token_lifecycle_over_hrng() {
        let mut gate = PinUvGate::new(true);
        let mut rng = TestRng(0xABCD);
        let mut token = [0u8; PIN_TOKEN_BYTES];
        assert_eq!(
            gate.issue_token(&mut rng, &mut token).unwrap_err(),
            CtapError::PinAuthInvalid
        );
        gate.set_key_agreement(true);
        gate.issue_token(&mut rng, &mut token).expect("token ok");
        assert!(token.iter().any(|&b| b != 0));
        gate.verify_token().expect("sessao viva");
        gate.invalidate_token();
        assert_eq!(gate.verify_token().unwrap_err(), CtapError::PinTokenExpired);
        let mut fresh = PinUvGate::new(false);
        fresh.set_key_agreement(true);
        assert_eq!(
            fresh.issue_token(&mut rng, &mut token).unwrap_err(),
            CtapError::PinNotSet
        );
    }

    #[test]
    fn uv_policy_and_block() {
        let mut gate = PinUvGate::new(true);
        assert_eq!(
            gate.check_uv_policy(true, false, false).unwrap_err(),
            CtapError::PinRequired
        );
        gate.check_uv_policy(true, false, true)
            .expect("pinAuth supre UV");
        for _ in 0..UV_MAX_RETRIES - 1 {
            assert_eq!(gate.record_uv_failure(), CtapError::UvInvalid);
        }
        assert_eq!(gate.record_uv_failure(), CtapError::UvBlocked);
        assert_eq!(
            gate.check_uv_policy(false, false, true).unwrap_err(),
            CtapError::UvBlocked
        );
    }

    #[test]
    fn up_binding_single_use_and_wrong_op() {
        let gate = PinUvGate::new(true);
        let policy = UpPolicy::with_default_window();
        let mut grant = policy.issue(op(7), 1_000);
        gate.check_up(&policy, &mut grant, op(7), 1_100)
            .expect("mesma operacao ok");
        assert_eq!(
            gate.check_up(&policy, &mut grant, op(7), 1_150)
                .unwrap_err(),
            CtapError::OperationDenied
        );
        let mut grant2 = policy.issue(op(7), 2_000);
        assert_eq!(
            gate.check_up(&policy, &mut grant2, op(9), 2_050)
                .unwrap_err(),
            CtapError::OperationDenied
        );
        let mut grant3 = policy.issue(op(7), 3_000);
        assert_eq!(
            gate.check_up(&policy, &mut grant3, op(7), 3_000 + 60_000 + 1)
                .unwrap_err(),
            CtapError::OperationDenied
        );
    }

    #[test]
    fn ecdh_hook_uses_real_curve_both_backends() {
        let mut secret = [0u8; 32];
        secret[31] = 1;
        let gx = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
        let mut peer = [0u8; 33];
        peer[0] = 0x03;
        for (i, c) in gx.as_bytes().chunks(2).enumerate() {
            let s = core::str::from_utf8(c).unwrap();
            peer[1 + i] = u8::from_str_radix(s, 16).unwrap();
        }
        let a = pin_key_agreement::<SoftwareP256>(&secret, &peer).expect("ecdh valido");
        let b = pin_key_agreement::<EspP256>(&secret, &peer).expect("ancora HW delega");
        assert_eq!(a, b);
        assert_eq!(
            pin_key_agreement::<SoftwareP256>(&secret, &[0x02]).unwrap_err(),
            CtapError::InvalidParameter
        );
    }

    #[test]
    fn hrng_mapping_never_leaks_sample() {
        assert_eq!(
            map_hrng_error(HrngError::StuckSample),
            CtapError::IntegrityFailure
        );
        assert_eq!(
            map_hrng_error(HrngError::Unsupported),
            CtapError::OperationDenied
        );
        assert_eq!(
            map_hrng_error(HrngError::TooLarge),
            CtapError::LimitExceeded
        );
    }

    #[test]
    fn debug_never_leaks_secret() {
        let mut gate = PinUvGate::new(true);
        gate.set_key_agreement(true);
        let mut rng = TestRng(99);
        let mut token = [0xABu8; PIN_TOKEN_BYTES];
        gate.issue_token(&mut rng, &mut token).expect("token ok");
        let dbg_gate = format!("{:?}", gate);
        let dbg_err = format!("{:?}", CtapError::PinAuthInvalid);
        assert!(dbg_gate.contains("PinUvGate"));
        assert!(dbg_gate.contains("pin_retries"));
        assert!(!dbg_gate.contains("ab"));
        assert!(!dbg_gate.contains("AB"));
        assert!(dbg_err.contains("0x33"));
        assert!(!dbg_err.contains("ab"));
    }
}
