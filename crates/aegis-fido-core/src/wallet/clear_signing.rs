//! Clear Signing Web3 Transaction Decoder & Decoupled 128x64 OLED Framebuffer (`OPP-06`)
//!
//! # Architecture
//! 1. **Zero-Mock Transaction Parser**:
//!    - **Ethereum**: Decodes EIP-1559 and Legacy transactions, extracting Chain ID,
//!      recipient `0x...`, Wei/ETH formatted value, and detects ERC-20 `transfer(address,uint256)`.
//!    - **Bitcoin**: Decodes raw transactions, extracting output addresses (P2WPKH, P2PKH),
//!      and satoshi/BTC amounts.
//!    - **Solana**: Decodes wire messages, identifying System Program Transfer instructions
//!      and lamport amounts.
//! 2. **Decoupled 128x64 OLED Framebuffer**:
//!    - Produces a 1024-byte (`[u8; 1024]`, 128 columns x 8 pages) SSD1306 framebuffer
//!      with an embedded 5x7 ASCII bitmap font in `no_std`.
//!    - Renders the 4 canonical security lines:
//!      1. `NETWORK`
//!      2. `TO ADDR`
//!      3. `AMOUNT`
//!      4. `PRESS GPIO0 TO SIGN`
//!    - 100% testable and runnable in pure code without requiring physical hardware display!

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use sha3::{Digest, Keccak256};

use crate::crypto::hash::sha256;

/// Framebuffer dimensions for SSD1306 I2C OLED display.
pub const OLED_WIDTH: usize = 128;
pub const OLED_HEIGHT: usize = 64;
pub const OLED_PAGES: usize = 8;
pub const OLED_BUFFER_SIZE: usize = OLED_WIDTH * OLED_PAGES; // 1024 bytes

/// ERC-20 transfer(address,uint256) 4-byte function selector (`0xa9059cbb`).
pub const ERC20_TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

/// Errors produced during transaction parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClearSignError {
    PayloadTooShort,
    InvalidRlpEncoding,
    InvalidEthereumTxType,
    InvalidBitcoinTx,
    InvalidSolanaMessage,
    UnsupportedContractCall,
}

impl core::fmt::Display for ClearSignError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PayloadTooShort => write!(f, "Transaction payload too short to parse"),
            Self::InvalidRlpEncoding => write!(f, "Invalid Ethereum RLP encoding"),
            Self::InvalidEthereumTxType => {
                write!(f, "Unsupported Ethereum transaction envelope type")
            }
            Self::InvalidBitcoinTx => write!(f, "Malformed Bitcoin raw transaction"),
            Self::InvalidSolanaMessage => write!(f, "Malformed Solana wire message"),
            Self::UnsupportedContractCall => write!(f, "Unsupported smart contract interaction"),
        }
    }
}

/// Human-readable clear-signing summary of a Web3 transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearSignTransactionSummary {
    /// Blockchain network name (e.g. "ETH (Mainnet)", "BTC", "SOL").
    pub network: String,
    /// Human-readable action (e.g. "Send ETH", "ERC-20 transfer", "Send BTC", "System Transfer").
    pub action: String,
    /// Destination address formatted for visual verification.
    pub to_address: String,
    /// Formatted transaction amount with token/coin symbol.
    pub amount: String,
    /// 32-byte transaction hash / digest.
    pub tx_hash: [u8; 32],
}

// --- Ethereum Parser (RLP + ERC-20) ---

/// Simple zero-copy RLP item view.
enum RlpItem<'a> {
    Data(&'a [u8]),
    List(&'a [u8]),
}

fn parse_rlp_item(input: &[u8]) -> Result<(RlpItem<'_>, &[u8]), ClearSignError> {
    if input.is_empty() {
        return Err(ClearSignError::PayloadTooShort);
    }
    let b0 = input[0];
    if b0 <= 0x7F {
        Ok((RlpItem::Data(&input[0..1]), &input[1..]))
    } else if b0 <= 0xB7 {
        let len = (b0 - 0x80) as usize;
        if input.len() < 1 + len {
            return Err(ClearSignError::InvalidRlpEncoding);
        }
        Ok((RlpItem::Data(&input[1..1 + len]), &input[1 + len..]))
    } else if b0 <= 0xBF {
        let len_of_len = (b0 - 0xB7) as usize;
        if input.len() < 1 + len_of_len {
            return Err(ClearSignError::InvalidRlpEncoding);
        }
        let mut len = 0usize;
        for &b in &input[1..1 + len_of_len] {
            len = (len << 8) | (b as usize);
        }
        let start = 1 + len_of_len;
        if input.len() < start + len {
            return Err(ClearSignError::InvalidRlpEncoding);
        }
        Ok((
            RlpItem::Data(&input[start..start + len]),
            &input[start + len..],
        ))
    } else if b0 <= 0xF7 {
        let len = (b0 - 0xC0) as usize;
        if input.len() < 1 + len {
            return Err(ClearSignError::InvalidRlpEncoding);
        }
        Ok((RlpItem::List(&input[1..1 + len]), &input[1 + len..]))
    } else {
        let len_of_len = (b0 - 0xF7) as usize;
        if input.len() < 1 + len_of_len {
            return Err(ClearSignError::InvalidRlpEncoding);
        }
        let mut len = 0usize;
        for &b in &input[1..1 + len_of_len] {
            len = (len << 8) | (b as usize);
        }
        let start = 1 + len_of_len;
        if input.len() < start + len {
            return Err(ClearSignError::InvalidRlpEncoding);
        }
        Ok((
            RlpItem::List(&input[start..start + len]),
            &input[start + len..],
        ))
    }
}

fn parse_rlp_list(mut payload: &[u8]) -> Result<Vec<&[u8]>, ClearSignError> {
    let mut items = Vec::new();
    while !payload.is_empty() {
        let (item, rest) = parse_rlp_item(payload)?;
        match item {
            RlpItem::Data(d) => items.push(d),
            RlpItem::List(l) => items.push(l),
        }
        payload = rest;
    }
    Ok(items)
}

/// Parses an Ethereum transaction (EIP-1559 type 0x02 or Legacy RLP).
pub fn parse_ethereum_tx(raw: &[u8]) -> Result<ClearSignTransactionSummary, ClearSignError> {
    if raw.is_empty() {
        return Err(ClearSignError::PayloadTooShort);
    }

    let mut hasher = Keccak256::new();
    hasher.update(raw);
    let mut tx_hash = [0u8; 32];
    tx_hash.copy_from_slice(&hasher.finalize());

    let (chain_name, to_bytes, value_bytes, data_bytes) = if raw[0] == 0x02 {
        // EIP-1559: 0x02 || RLP([chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data, ...])
        let (root, _) = parse_rlp_item(&raw[1..])?;
        let list_bytes = match root {
            RlpItem::List(l) => l,
            _ => return Err(ClearSignError::InvalidRlpEncoding),
        };
        let fields = parse_rlp_list(list_bytes)?;
        if fields.len() < 8 {
            return Err(ClearSignError::InvalidRlpEncoding);
        }
        let chain_id = if fields[0].is_empty() {
            1u64
        } else {
            fields[0][0] as u64
        };
        let net = match chain_id {
            1 => String::from("ETH (Mainnet)"),
            11155111 => String::from("ETH (Sepolia)"),
            _ => format!("ETH (Chain {})", chain_id),
        };
        (net, fields[5], fields[6], fields[7])
    } else {
        // Legacy: RLP([nonce, gas_price, gas_limit, to, value, data, v, r, s])
        let (root, _) = parse_rlp_item(raw)?;
        let list_bytes = match root {
            RlpItem::List(l) => l,
            _ => return Err(ClearSignError::InvalidRlpEncoding),
        };
        let fields = parse_rlp_list(list_bytes)?;
        if fields.len() < 6 {
            return Err(ClearSignError::InvalidRlpEncoding);
        }
        (
            String::from("ETH (Legacy)"),
            fields[3],
            fields[4],
            fields[5],
        )
    };

    // Check for ERC-20 transfer: 4-byte selector 0xa9059cbb + 32-byte address + 32-byte amount
    if data_bytes.len() >= 68 && data_bytes[0..4] == ERC20_TRANSFER_SELECTOR {
        let recipient_bytes = &data_bytes[16..36];
        let amount_bytes = &data_bytes[36..68];
        let to_addr = format_eth_address(recipient_bytes);
        let amount = format_hex_amount(amount_bytes, "Token");
        return Ok(ClearSignTransactionSummary {
            network: chain_name,
            action: String::from("ERC-20 transfer"),
            to_address: to_addr,
            amount,
            tx_hash,
        });
    }

    let to_addr = format_eth_address(to_bytes);
    let amount = format_wei_amount(value_bytes);

    Ok(ClearSignTransactionSummary {
        network: chain_name,
        action: String::from("Send ETH"),
        to_address: to_addr,
        amount,
        tx_hash,
    })
}

fn format_eth_address(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::from("0x0000000000000000000000000000000000000000");
    }
    format!("0x{}", hex::encode(bytes))
}

fn format_wei_amount(bytes: &[u8]) -> String {
    if bytes.is_empty() || bytes == [0] {
        return String::from("0.000000 ETH");
    }
    // Read big-endian up to u128
    let mut val = 0u128;
    for &b in bytes {
        val = (val << 8) | (b as u128);
    }
    let eth_whole = val / 1_000_000_000_000_000_000;
    let eth_rem = (val % 1_000_000_000_000_000_000) / 1_000_000_000_000; // 6 decimal digits
    format!("{}.{:06} ETH", eth_whole, eth_rem)
}

fn format_hex_amount(bytes: &[u8], symbol: &str) -> String {
    let mut val = 0u128;
    for &b in bytes.iter().take(16) {
        val = (val << 8) | (b as u128);
    }
    format!("{} {}", val, symbol)
}

// --- Bitcoin Parser ---

/// Parses a raw Bitcoin transaction extracting the primary destination and satoshis.
pub fn parse_bitcoin_tx(raw: &[u8]) -> Result<ClearSignTransactionSummary, ClearSignError> {
    if raw.len() < 10 {
        return Err(ClearSignError::PayloadTooShort);
    }

    // Double-SHA256 for txid
    let hash1 = sha256(raw);
    let hash2 = sha256(&hash1);
    let mut tx_hash = hash2;
    tx_hash.reverse(); // txid is displayed in reverse byte order

    // Simple Bitcoin wire scanner
    let mut cursor = 4; // version (4 bytes)

    // Input count
    if cursor >= raw.len() {
        return Err(ClearSignError::InvalidBitcoinTx);
    }
    let (in_count, len_bytes) = read_varint(&raw[cursor..])?;
    cursor += len_bytes;

    // Skip inputs
    for _ in 0..in_count {
        if cursor + 36 > raw.len() {
            return Err(ClearSignError::InvalidBitcoinTx);
        }
        cursor += 36; // txid (32) + vout (4)
        let (script_len, sl_bytes) = read_varint(&raw[cursor..])?;
        cursor += sl_bytes + (script_len as usize) + 4; // script + sequence (4)
    }

    // Output count
    if cursor >= raw.len() {
        return Err(ClearSignError::InvalidBitcoinTx);
    }
    let (out_count, len_bytes) = read_varint(&raw[cursor..])?;
    cursor += len_bytes;

    if out_count == 0 || cursor + 8 > raw.len() {
        return Err(ClearSignError::InvalidBitcoinTx);
    }

    // First output: 8-byte value (little-endian sats) + scriptPubKey
    let mut sats_bytes = [0u8; 8];
    sats_bytes.copy_from_slice(&raw[cursor..cursor + 8]);
    let sats = u64::from_le_bytes(sats_bytes);
    cursor += 8;

    let (script_len, sl_bytes) = read_varint(&raw[cursor..])?;
    cursor += sl_bytes;
    let end_script = cursor + (script_len as usize);
    if end_script > raw.len() {
        return Err(ClearSignError::InvalidBitcoinTx);
    }
    let script = &raw[cursor..end_script];

    // Format destination address
    let to_addr = if script.len() == 22 && script[0] == 0x00 && script[1] == 0x14 {
        // P2WPKH: witness v0 20 bytes
        format!("bc1q{}", hex::encode(&script[2..22]))
    } else if script.len() == 25 && script[0] == 0x76 && script[1] == 0xA9 {
        // P2PKH: 1...
        format!("1{}", hex::encode(&script[3..23]))
    } else {
        format!("0x{}", hex::encode(script))
    };

    let btc_whole = sats / 100_000_000;
    let btc_rem = sats % 100_000_000;
    let amount_str = format!("{}.{:08} BTC ({} sats)", btc_whole, btc_rem, sats);

    Ok(ClearSignTransactionSummary {
        network: String::from("BTC (Bitcoin)"),
        action: String::from("Send BTC"),
        to_address: to_addr,
        amount: amount_str,
        tx_hash,
    })
}

fn read_varint(input: &[u8]) -> Result<(u64, usize), ClearSignError> {
    if input.is_empty() {
        return Err(ClearSignError::PayloadTooShort);
    }
    match input[0] {
        0..=0xFC => Ok((input[0] as u64, 1)),
        0xFD => {
            if input.len() < 3 {
                return Err(ClearSignError::PayloadTooShort);
            }
            let val = u16::from_le_bytes([input[1], input[2]]) as u64;
            Ok((val, 3))
        }
        0xFE => {
            if input.len() < 5 {
                return Err(ClearSignError::PayloadTooShort);
            }
            let val = u32::from_le_bytes([input[1], input[2], input[3], input[4]]) as u64;
            Ok((val, 5))
        }
        0xFF => {
            if input.len() < 9 {
                return Err(ClearSignError::PayloadTooShort);
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&input[1..9]);
            Ok((u64::from_le_bytes(b), 9))
        }
    }
}

// --- Solana Parser ---

/// Parses a Solana wire message identifying System Program Transfers.
pub fn parse_solana_tx(raw: &[u8]) -> Result<ClearSignTransactionSummary, ClearSignError> {
    if raw.len() < 35 {
        return Err(ClearSignError::PayloadTooShort);
    }

    let tx_hash = sha256(raw);

    let mut cursor = 3; // Skip header (3 bytes)
    let (acct_count, len_bytes) = read_varint(&raw[cursor..])?;
    cursor += len_bytes;

    let acct_count = acct_count as usize;
    if cursor + acct_count * 32 + 32 > raw.len() {
        return Err(ClearSignError::InvalidSolanaMessage);
    }

    let accounts = &raw[cursor..cursor + acct_count * 32];
    cursor += acct_count * 32;

    // Recent blockhash
    cursor += 32;

    // Instructions count
    if cursor >= raw.len() {
        return Err(ClearSignError::InvalidSolanaMessage);
    }
    let (ix_count, len_bytes) = read_varint(&raw[cursor..])?;
    cursor += len_bytes;

    if ix_count == 0 || cursor >= raw.len() {
        return Err(ClearSignError::InvalidSolanaMessage);
    }

    // Inspect first instruction
    let _prog_id_idx = raw[cursor] as usize;
    cursor += 1;

    let (ix_accts_len, len_bytes) = read_varint(&raw[cursor..])?;
    cursor += len_bytes;
    if cursor + (ix_accts_len as usize) > raw.len() {
        return Err(ClearSignError::InvalidSolanaMessage);
    }
    let ix_accts = &raw[cursor..cursor + (ix_accts_len as usize)];
    cursor += ix_accts_len as usize;

    let (ix_data_len, len_bytes) = read_varint(&raw[cursor..])?;
    cursor += len_bytes;
    if cursor + (ix_data_len as usize) > raw.len() {
        return Err(ClearSignError::InvalidSolanaMessage);
    }
    let ix_data = &raw[cursor..cursor + (ix_data_len as usize)];

    // Check System Transfer: opcode 2 (4 bytes LE) + lamports (8 bytes LE)
    if ix_data.len() >= 12 && ix_data[0..4] == [2, 0, 0, 0] {
        let mut lamp_bytes = [0u8; 8];
        lamp_bytes.copy_from_slice(&ix_data[4..12]);
        let lamports = u64::from_le_bytes(lamp_bytes);

        // Destination account is typically index 1 in System Transfer
        let dest_idx = if ix_accts.len() >= 2 {
            ix_accts[1] as usize
        } else {
            0
        };
        let dest_pubkey = if dest_idx < acct_count {
            &accounts[dest_idx * 32..(dest_idx + 1) * 32]
        } else {
            &accounts[0..32]
        };

        let to_addr = format!("SOL:{}", hex::encode(&dest_pubkey[0..16]));
        let sol_whole = lamports / 1_000_000_000;
        let sol_rem = lamports % 1_000_000_000;
        let amount_str = format!("{}.{:06} SOL", sol_whole, sol_rem / 1000);

        return Ok(ClearSignTransactionSummary {
            network: String::from("SOL (Solana)"),
            action: String::from("System Transfer"),
            to_address: to_addr,
            amount: amount_str,
            tx_hash,
        });
    }

    Ok(ClearSignTransactionSummary {
        network: String::from("SOL (Solana)"),
        action: String::from("Transaction"),
        to_address: String::from("Contract/Program"),
        amount: String::from("0.000000 SOL"),
        tx_hash,
    })
}

// --- 5x7 ASCII Bitmap Font Table (ASCII 0x20 Space to 0x7E '~') ---

static FONT_5X7: [[u8; 5]; 95] = [
    [0x00, 0x00, 0x00, 0x00, 0x00], // ' ' 0x20
    [0x00, 0x00, 0x5F, 0x00, 0x00], // '!'
    [0x00, 0x07, 0x00, 0x07, 0x00], // '"'
    [0x14, 0x7F, 0x14, 0x7F, 0x14], // '#'
    [0x24, 0x2A, 0x7F, 0x2A, 0x12], // '$'
    [0x23, 0x13, 0x08, 0x64, 0x62], // '%'
    [0x36, 0x49, 0x55, 0x22, 0x50], // '&'
    [0x00, 0x05, 0x03, 0x00, 0x00], // '''
    [0x00, 0x1C, 0x22, 0x41, 0x00], // '('
    [0x00, 0x41, 0x22, 0x1C, 0x00], // ')'
    [0x14, 0x08, 0x3E, 0x08, 0x14], // '*'
    [0x08, 0x08, 0x3E, 0x08, 0x08], // '+'
    [0x00, 0x50, 0x30, 0x00, 0x00], // ','
    [0x08, 0x08, 0x08, 0x08, 0x08], // '-'
    [0x00, 0x60, 0x60, 0x00, 0x00], // '.'
    [0x20, 0x10, 0x08, 0x04, 0x02], // '/'
    [0x3E, 0x51, 0x49, 0x45, 0x3E], // '0' 0x30
    [0x00, 0x42, 0x7F, 0x40, 0x00], // '1'
    [0x42, 0x61, 0x51, 0x49, 0x46], // '2'
    [0x21, 0x41, 0x45, 0x4B, 0x31], // '3'
    [0x18, 0x14, 0x12, 0x7F, 0x10], // '4'
    [0x27, 0x45, 0x45, 0x45, 0x39], // '5'
    [0x3C, 0x4A, 0x49, 0x49, 0x30], // '6'
    [0x01, 0x71, 0x09, 0x05, 0x03], // '7'
    [0x36, 0x49, 0x49, 0x49, 0x36], // '8'
    [0x06, 0x49, 0x49, 0x29, 0x1E], // '9'
    [0x00, 0x36, 0x36, 0x00, 0x00], // ':'
    [0x00, 0x56, 0x36, 0x00, 0x00], // ';'
    [0x08, 0x14, 0x22, 0x41, 0x00], // '<'
    [0x14, 0x14, 0x14, 0x14, 0x14], // '='
    [0x00, 0x41, 0x22, 0x14, 0x08], // '>'
    [0x02, 0x01, 0x51, 0x09, 0x06], // '?'
    [0x32, 0x49, 0x79, 0x41, 0x3E], // '@' 0x40
    [0x7E, 0x11, 0x11, 0x11, 0x7E], // 'A'
    [0x7F, 0x49, 0x49, 0x49, 0x36], // 'B'
    [0x3E, 0x41, 0x41, 0x41, 0x22], // 'C'
    [0x7F, 0x41, 0x41, 0x22, 0x1C], // 'D'
    [0x7F, 0x49, 0x49, 0x49, 0x41], // 'E'
    [0x7F, 0x09, 0x09, 0x09, 0x01], // 'F'
    [0x3E, 0x41, 0x49, 0x49, 0x7A], // 'G'
    [0x7F, 0x08, 0x08, 0x08, 0x7F], // 'H'
    [0x00, 0x41, 0x7F, 0x41, 0x00], // 'I'
    [0x20, 0x40, 0x41, 0x3F, 0x01], // 'J'
    [0x7F, 0x08, 0x14, 0x22, 0x41], // 'K'
    [0x7F, 0x40, 0x40, 0x40, 0x40], // 'L'
    [0x7F, 0x02, 0x0C, 0x02, 0x7F], // 'M'
    [0x7F, 0x04, 0x08, 0x10, 0x7F], // 'N'
    [0x3E, 0x41, 0x41, 0x41, 0x3E], // 'O'
    [0x7F, 0x09, 0x09, 0x09, 0x06], // 'P'
    [0x3E, 0x41, 0x51, 0x21, 0x5E], // 'Q'
    [0x7F, 0x09, 0x19, 0x29, 0x46], // 'R'
    [0x46, 0x49, 0x49, 0x49, 0x31], // 'S'
    [0x01, 0x01, 0x7F, 0x01, 0x01], // 'T'
    [0x3F, 0x40, 0x40, 0x40, 0x3F], // 'U'
    [0x1F, 0x20, 0x40, 0x20, 0x1F], // 'V'
    [0x3F, 0x40, 0x38, 0x40, 0x3F], // 'W'
    [0x63, 0x14, 0x08, 0x14, 0x63], // 'X'
    [0x07, 0x08, 0x70, 0x08, 0x07], // 'Y'
    [0x61, 0x51, 0x49, 0x45, 0x43], // 'Z'
    [0x00, 0x7F, 0x41, 0x41, 0x00], // '[' 0x5B
    [0x02, 0x04, 0x08, 0x10, 0x20], // '\'
    [0x00, 0x41, 0x41, 0x7F, 0x00], // ']'
    [0x04, 0x02, 0x01, 0x02, 0x04], // '^'
    [0x40, 0x40, 0x40, 0x40, 0x40], // '_'
    [0x00, 0x01, 0x02, 0x04, 0x00], // '`' 0x60
    [0x20, 0x54, 0x54, 0x54, 0x78], // 'a'
    [0x7F, 0x48, 0x44, 0x44, 0x38], // 'b'
    [0x38, 0x44, 0x44, 0x44, 0x20], // 'c'
    [0x38, 0x44, 0x44, 0x48, 0x7F], // 'd'
    [0x38, 0x54, 0x54, 0x54, 0x18], // 'e'
    [0x08, 0x7E, 0x09, 0x01, 0x02], // 'f'
    [0x0C, 0x52, 0x52, 0x52, 0x3E], // 'g'
    [0x7F, 0x08, 0x04, 0x04, 0x78], // 'h'
    [0x00, 0x44, 0x7D, 0x40, 0x00], // 'i'
    [0x20, 0x40, 0x44, 0x3D, 0x00], // 'j'
    [0x7F, 0x10, 0x28, 0x44, 0x00], // 'k'
    [0x00, 0x41, 0x7F, 0x40, 0x00], // 'l'
    [0x7C, 0x04, 0x18, 0x04, 0x78], // 'm'
    [0x7C, 0x08, 0x04, 0x04, 0x78], // 'n'
    [0x38, 0x44, 0x44, 0x44, 0x38], // 'o'
    [0x7C, 0x14, 0x14, 0x14, 0x08], // 'p'
    [0x08, 0x14, 0x14, 0x18, 0x7C], // 'q'
    [0x7C, 0x08, 0x04, 0x04, 0x08], // 'r'
    [0x48, 0x54, 0x54, 0x54, 0x20], // 's'
    [0x04, 0x3F, 0x44, 0x40, 0x20], // 't'
    [0x3C, 0x40, 0x40, 0x20, 0x7C], // 'u'
    [0x1C, 0x20, 0x40, 0x20, 0x1C], // 'v'
    [0x3C, 0x40, 0x30, 0x40, 0x3C], // 'w'
    [0x44, 0x28, 0x10, 0x28, 0x44], // 'x'
    [0x0C, 0x50, 0x50, 0x50, 0x3C], // 'y'
    [0x44, 0x64, 0x54, 0x4C, 0x44], // 'z'
    [0x00, 0x08, 0x36, 0x41, 0x00], // '{'
    [0x00, 0x00, 0x7F, 0x00, 0x00], // '|'
    [0x00, 0x41, 0x36, 0x08, 0x00], // '}'
    [0x08, 0x08, 0x2A, 0x1C, 0x08], // '~'
];

/// Pixel matrix renderer representing a 128x64 SSD1306 monochrome OLED display.
#[derive(Clone, PartialEq, Eq)]
pub struct OledFrame128x64 {
    /// 1024-byte framebuffer: 8 vertical pages x 128 columns.
    pub buffer: [u8; OLED_BUFFER_SIZE],
}

impl core::fmt::Debug for OledFrame128x64 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "OledFrame128x64(1024 bytes)")
    }
}

impl Default for OledFrame128x64 {
    fn default() -> Self {
        Self::new()
    }
}

impl OledFrame128x64 {
    /// Initializes an empty display frame (all pixels off).
    pub fn new() -> Self {
        Self {
            buffer: [0u8; OLED_BUFFER_SIZE],
        }
    }

    /// Clears the entire frame buffer.
    pub fn clear(&mut self) {
        self.buffer.fill(0);
    }

    /// Sets pixel at coordinate `(x, y)` where `x < 128` and `y < 64`.
    pub fn set_pixel(&mut self, x: usize, y: usize, on: bool) {
        if x < OLED_WIDTH && y < OLED_HEIGHT {
            let page = y / 8;
            let bit = y % 8;
            let idx = page * OLED_WIDTH + x;
            if on {
                self.buffer[idx] |= 1 << bit;
            } else {
                self.buffer[idx] &= !(1 << bit);
            }
        }
    }

    /// Draws a single ASCII character onto the specified page and column.
    pub fn draw_char(&mut self, col: usize, page: usize, c: char) -> usize {
        if page >= OLED_PAGES || col >= OLED_WIDTH {
            return col;
        }

        let glyph_idx = match c as u32 {
            0x20..=0x7E => (c as usize) - 0x20,
            _ => 0, // Fallback to space
        };

        let glyph = &FONT_5X7[glyph_idx];
        for (i, &col_bits) in glyph.iter().enumerate() {
            let x = col + i;
            if x < OLED_WIDTH {
                let idx = page * OLED_WIDTH + x;
                self.buffer[idx] |= col_bits;
            }
        }

        col + 6 // 5 pixels glyph + 1 pixel inter-character space
    }

    /// Draws a text string onto the given page starting at `col`. Truncates cleanly if exceeding 128 columns.
    pub fn draw_str(&mut self, mut col: usize, page: usize, text: &str) {
        for c in text.chars() {
            if col + 5 >= OLED_WIDTH {
                break;
            }
            col = self.draw_char(col, page, c);
        }
    }

    /// Renders the 4 standard clear-signing security lines onto the 128x64 framebuffer:
    /// - Page 0: `NETWORK` & Action
    /// - Page 2: `TO ADDR` (truncated for safety)
    /// - Page 4: `AMOUNT`
    /// - Page 6: `[PRESS GPIO0 TO SIGN]` (highlight banner)
    pub fn render_transaction_preview(&mut self, summary: &ClearSignTransactionSummary) {
        self.clear();

        // Line 1 (Page 0): Network & Action
        let line1 = format!("{}: {}", summary.network, summary.action);
        self.draw_str(2, 0, &line1);

        // Line 2 (Page 2): Destination address
        let to_display = if summary.to_address.len() > 18 {
            format!(
                "TO: {}...{}",
                &summary.to_address[0..8],
                &summary.to_address[summary.to_address.len() - 6..]
            )
        } else {
            format!("TO: {}", summary.to_address)
        };
        self.draw_str(2, 2, &to_display);

        // Line 3 (Page 4): Amount
        let line3 = format!("AMT: {}", summary.amount);
        self.draw_str(2, 4, &line3);

        // Line 4 (Page 6): Security confirmation banner
        self.draw_str(2, 6, "PRESS GPIO0 TO SIGN");

        // Optional decorative horizontal separator on page 1
        for x in 0..OLED_WIDTH {
            self.buffer[OLED_WIDTH + x] |= 0x01;
        }
    }

    /// Returns reference to raw 1024-byte framebuffer.
    pub fn as_bytes(&self) -> &[u8; OLED_BUFFER_SIZE] {
        &self.buffer
    }

    /// Renders the display into ASCII text art for headless tests and debug logs.
    pub fn to_ascii_art(&self) -> String {
        let mut art = String::with_capacity((OLED_WIDTH + 1) * OLED_HEIGHT);
        for y in 0..OLED_HEIGHT {
            let page = y / 8;
            let bit = y % 8;
            for x in 0..OLED_WIDTH {
                let idx = page * OLED_WIDTH + x;
                let is_on = (self.buffer[idx] & (1 << bit)) != 0;
                art.push(if is_on { '#' } else { '.' });
            }
            art.push('\n');
        }
        art
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethereum_eip1559_parsing() {
        // Construct a synthetic EIP-1559 transaction:
        // 0x02 || RLP([chain_id=1, nonce=0, max_priority=2, max_fee=20, gas_limit=21000, to=0x71C..., value=1 ETH (0x0DE0B6B3A7640000), data=""])
        let to_addr = [0x71u8; 20];
        let val_1_eth = 1_000_000_000_000_000_000u128.to_be_bytes(); // 16 bytes

        let mut rlp_fields = alloc::vec![
            0x01, // chain_id = 1
            0x80, // nonce = 0 (0x80)
            0x02, // max_priority = 2
            0x14, // max_fee = 20
        ];
        // gas_limit = 21000 (0x5208)
        rlp_fields.extend_from_slice(&[0x82, 0x52, 0x08]);
        // to = 20 bytes (0x94 || 20 bytes)
        rlp_fields.push(0x94);
        rlp_fields.extend_from_slice(&to_addr);
        // value = 1 ETH (0x88 || 8 bytes)
        rlp_fields.push(0x88);
        rlp_fields.extend_from_slice(&val_1_eth[8..16]);
        // data = empty (0x80)
        rlp_fields.push(0x80);

        let mut raw_tx = alloc::vec![0x02]; // EIP-1559 type
                                            // RLP list header
        let list_len = rlp_fields.len();
        raw_tx.push(0xC0 + (list_len as u8));
        raw_tx.extend_from_slice(&rlp_fields);

        let parsed = parse_ethereum_tx(&raw_tx).expect("parse eth");
        assert_eq!(parsed.network, "ETH (Mainnet)");
        assert_eq!(parsed.action, "Send ETH");
        assert!(parsed.to_address.starts_with("0x7171"));
        assert!(parsed.amount.contains("1.000000 ETH"));
    }

    #[test]
    fn test_ethereum_erc20_transfer_detection() {
        let contract_addr = [0xCCu8; 20];
        let token_recipient = [0xD1u8; 20];
        let token_amount = [0x05u8; 32];

        let mut data = Vec::new();
        data.extend_from_slice(&ERC20_TRANSFER_SELECTOR); // 0xa9059cbb
                                                          // 12 bytes zero padding + 20 bytes recipient
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(&token_recipient);
        // 32 bytes amount
        data.extend_from_slice(&token_amount);

        let mut rlp_fields = alloc::vec![
            0x01, // chain_id = 1
            0x80, // nonce
            0x02, // priority
            0x14, // fee
        ];
        rlp_fields.extend_from_slice(&[0x82, 0x52, 0x08]); // gas
        rlp_fields.push(0x94); // contract address
        rlp_fields.extend_from_slice(&contract_addr);
        rlp_fields.push(0x80); // value = 0 ETH
                               // data (68 bytes: 0xB8, 68, bytes)
        rlp_fields.extend_from_slice(&[0xB8, 68]);
        rlp_fields.extend_from_slice(&data);

        let mut raw_tx = alloc::vec![0x02];
        let list_len = rlp_fields.len();
        raw_tx.extend_from_slice(&[0xF8, list_len as u8]);
        raw_tx.extend_from_slice(&rlp_fields);

        let parsed = parse_ethereum_tx(&raw_tx).expect("parse erc20");
        assert_eq!(parsed.action, "ERC-20 transfer");
        assert!(parsed.to_address.contains("d1d1d1"));
    }

    #[test]
    fn test_oled_frame_render_preview() {
        let summary = ClearSignTransactionSummary {
            network: String::from("ETH"),
            action: String::from("Send"),
            to_address: String::from("0x71C95911E9a5D330f4d621432f74136C9543Ea91"),
            amount: String::from("1.500000 ETH"),
            tx_hash: [0xAAu8; 32],
        };

        let mut frame = OledFrame128x64::new();
        frame.render_transaction_preview(&summary);

        // Verify that pixels were drawn on page 0, 2, 4, 6
        let has_pixels_p0 = frame.buffer[0..128].iter().any(|&b| b != 0);
        let has_pixels_p2 = frame.buffer[256..384].iter().any(|&b| b != 0);
        let has_pixels_p4 = frame.buffer[512..640].iter().any(|&b| b != 0);
        let has_pixels_p6 = frame.buffer[768..896].iter().any(|&b| b != 0);

        assert!(has_pixels_p0);
        assert!(has_pixels_p2);
        assert!(has_pixels_p4);
        assert!(has_pixels_p6);

        let ascii_art = frame.to_ascii_art();
        assert!(ascii_art.contains('#'));
        assert_eq!(frame.as_bytes().len(), 1024);
    }
}
