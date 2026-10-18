//! CTAP 2.1 / 2.3 Status Codes and Error Definitions

pub const CTAP1_ERR_SUCCESS: u8 = 0x00;
pub const CTAP1_ERR_INVALID_COMMAND: u8 = 0x01;
pub const CTAP1_ERR_INVALID_PARAMETER: u8 = 0x02;
pub const CTAP1_ERR_INVALID_LENGTH: u8 = 0x03;
pub const CTAP1_ERR_INVALID_SEQ: u8 = 0x04;
pub const CTAP1_ERR_TIMEOUT: u8 = 0x05;
pub const CTAP1_ERR_CHANNEL_BUSY: u8 = 0x06;

pub const CTAP2_ERR_CBOR_UNEXPECTED_TYPE: u8 = 0x11;
pub const CTAP2_ERR_INVALID_CBOR: u8 = 0x12;
pub const CTAP2_ERR_MISSING_PARAMETER: u8 = 0x14;
pub const CTAP2_ERR_LIMIT_EXCEEDED: u8 = 0x15;
pub const CTAP2_ERR_UNSUPPORTED_EXTENSION: u8 = 0x16;
pub const CTAP2_ERR_CREDENTIAL_EXCLUDED: u8 = 0x19;
pub const CTAP2_ERR_PROCESSING: u8 = 0x21;
pub const CTAP2_ERR_INVALID_CREDENTIAL: u8 = 0x22;
pub const CTAP2_ERR_USER_ACTION_PENDING: u8 = 0x23;
pub const CTAP2_ERR_OPERATION_PENDING: u8 = 0x24;
pub const CTAP2_ERR_NO_OPERATIONS: u8 = 0x25;
pub const CTAP2_ERR_UNSUPPORTED_ALGORITHM: u8 = 0x26;
pub const CTAP2_ERR_OPERATION_DENIED: u8 = 0x27;
pub const CTAP2_ERR_KEY_STORE_FULL: u8 = 0x28;
pub const CTAP2_ERR_UNSUPPORTED_OPTION: u8 = 0x2B;
pub const CTAP2_ERR_INVALID_OPTION: u8 = 0x2C;
pub const CTAP2_ERR_KEEPALIVE_CANCEL: u8 = 0x2D;
pub const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2E;
pub const CTAP2_ERR_USER_ACTION_TIMEOUT: u8 = 0x2F;
pub const CTAP2_ERR_NOT_ALLOWED: u8 = 0x30;
pub const CTAP2_ERR_PIN_INVALID: u8 = 0x31;
pub const CTAP2_ERR_PIN_BLOCKED: u8 = 0x32;
pub const CTAP2_ERR_PIN_AUTH_INVALID: u8 = 0x33;
pub const CTAP2_ERR_PIN_AUTH_BLOCKED: u8 = 0x34;
pub const CTAP2_ERR_PIN_NOT_SET: u8 = 0x35;
pub const CTAP2_ERR_PIN_REQUIRED: u8 = 0x36;
pub const CTAP2_ERR_PIN_POLICY_VIOLATION: u8 = 0x37;
pub const CTAP2_ERR_PIN_TOKEN_EXPIRED: u8 = 0x38;
pub const CTAP2_ERR_REQUEST_AND_KEY_MISMATCH: u8 = 0x39;
pub const CTAP2_ERR_TOO_MANY_PIN_ATTEMPTS: u8 = 0x3A;
pub const CTAP2_ERR_PIN_KEY_STORE_FULL: u8 = 0x37;
pub const CTAP2_ERR_U2F_PIN_POLICY_VIOLATION: u8 = 0x38;
pub const CTAP2_ERR_DISALLOWED_BY_CONFIG: u8 = 0x39;
pub const CTAP2_ERR_INTEGRITY_FAILURE: u8 = 0x3B;
pub const CTAP2_ERR_INVALID_SUBCOMMAND: u8 = 0x3C;
pub const CTAP2_ERR_UV_INVALID: u8 = 0x3D;
pub const CTAP2_ERR_UV_BLOCKED: u8 = 0x3E;
pub const CTAP2_ERR_UNAUTHORIZED_PERMISSION: u8 = 0x3F;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CtapError {
    Success,
    InvalidCommand,
    InvalidParameter,
    InvalidLength,
    InvalidSeq,
    Timeout,
    ChannelBusy,
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
    RequestAndKeyMismatch,
    TooManyPinAttempts,
    PinKeyStoreFull,
    DisallowedByConfig,
    IntegrityFailure,
    InvalidSubcommand,
    UvInvalid,
    UvBlocked,
    UnauthorizedPermission,
    Other(u8),
}

impl CtapError {
    pub fn to_status_code(self) -> u8 {
        match self {
            Self::Success => CTAP1_ERR_SUCCESS,
            Self::InvalidCommand => CTAP1_ERR_INVALID_COMMAND,
            Self::InvalidParameter => CTAP1_ERR_INVALID_PARAMETER,
            Self::InvalidLength => CTAP1_ERR_INVALID_LENGTH,
            Self::InvalidSeq => CTAP1_ERR_INVALID_SEQ,
            Self::Timeout => CTAP1_ERR_TIMEOUT,
            Self::ChannelBusy => CTAP1_ERR_CHANNEL_BUSY,
            Self::CborUnexpectedType => CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
            Self::InvalidCbor => CTAP2_ERR_INVALID_CBOR,
            Self::MissingParameter => CTAP2_ERR_MISSING_PARAMETER,
            Self::LimitExceeded => CTAP2_ERR_LIMIT_EXCEEDED,
            Self::UnsupportedExtension => CTAP2_ERR_UNSUPPORTED_EXTENSION,
            Self::CredentialExcluded => CTAP2_ERR_CREDENTIAL_EXCLUDED,
            Self::Processing => CTAP2_ERR_PROCESSING,
            Self::InvalidCredential => CTAP2_ERR_INVALID_CREDENTIAL,
            Self::UserActionPending => CTAP2_ERR_USER_ACTION_PENDING,
            Self::OperationPending => CTAP2_ERR_OPERATION_PENDING,
            Self::NoOperations => CTAP2_ERR_NO_OPERATIONS,
            Self::UnsupportedAlgorithm => CTAP2_ERR_UNSUPPORTED_ALGORITHM,
            Self::OperationDenied => CTAP2_ERR_OPERATION_DENIED,
            Self::KeyStoreFull => CTAP2_ERR_KEY_STORE_FULL,
            Self::UnsupportedOption => CTAP2_ERR_UNSUPPORTED_OPTION,
            Self::InvalidOption => CTAP2_ERR_INVALID_OPTION,
            Self::KeepaliveCancel => CTAP2_ERR_KEEPALIVE_CANCEL,
            Self::NoCredentials => CTAP2_ERR_NO_CREDENTIALS,
            Self::UserActionTimeout => CTAP2_ERR_USER_ACTION_TIMEOUT,
            Self::NotAllowed => CTAP2_ERR_NOT_ALLOWED,
            Self::PinInvalid => CTAP2_ERR_PIN_INVALID,
            Self::PinBlocked => CTAP2_ERR_PIN_BLOCKED,
            Self::PinAuthInvalid => CTAP2_ERR_PIN_AUTH_INVALID,
            Self::PinAuthBlocked => CTAP2_ERR_PIN_AUTH_BLOCKED,
            Self::PinNotSet => CTAP2_ERR_PIN_NOT_SET,
            Self::PinRequired => CTAP2_ERR_PIN_REQUIRED,
            Self::PinPolicyViolation => CTAP2_ERR_PIN_POLICY_VIOLATION,
            Self::PinTokenExpired => CTAP2_ERR_PIN_TOKEN_EXPIRED,
            Self::RequestAndKeyMismatch => CTAP2_ERR_REQUEST_AND_KEY_MISMATCH,
            Self::TooManyPinAttempts => CTAP2_ERR_TOO_MANY_PIN_ATTEMPTS,
            Self::PinKeyStoreFull => CTAP2_ERR_PIN_KEY_STORE_FULL,
            Self::DisallowedByConfig => CTAP2_ERR_DISALLOWED_BY_CONFIG,
            Self::IntegrityFailure => CTAP2_ERR_INTEGRITY_FAILURE,
            Self::InvalidSubcommand => CTAP2_ERR_INVALID_SUBCOMMAND,
            Self::UvInvalid => CTAP2_ERR_UV_INVALID,
            Self::UvBlocked => CTAP2_ERR_UV_BLOCKED,
            Self::UnauthorizedPermission => CTAP2_ERR_UNAUTHORIZED_PERMISSION,
            Self::Other(code) => code,
        }
    }
}
