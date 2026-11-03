//! OATH provider contract: trait definition.
//!
//! Secret storage/calculation live in firmware; never here.

use crate::error::SdkError;
use crate::request::OathRequest;
use crate::response::SdkResponse;

/// Executes [`OathRequest`] (vendor `0x24`-`0x27`, HTTP `GET /oath/code`).
pub trait OathProvider {
    /// Execute one OATH request.
    fn execute(request: OathRequest) -> Result<SdkResponse, SdkError>;
}
