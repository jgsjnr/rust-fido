//! PIV APDU field parsers (BER-TLV curto + objetos GET/PUT/GEN/AUTH).
//!
//! Dono unico dos parsers de campo APDU do PIV. `piv_cmd` consome via
//! `super::apdu` (nunca duplicar parser). O parser de bytes crus do fio
//! (`CommandApdu::parse`) mora no transporte (`crate::ccid`) e nao muda.

use crate::ccid::PIV_TAG_X509_CERT;
use alloc::vec::Vec;

/// Lê `len` BER-TLV curta (`<128`), `81 XX` ou `82 XX XX` em `pos`.
/// Retorna `(tamanho, bytes_do_campo_len)`; `None` = malformado.
fn read_len(data: &[u8], pos: usize) -> Option<(usize, usize)> {
    let first = *data.get(pos)?;
    if first < 0x80 {
        return Some((first as usize, 1));
    }
    if first == 0x81 {
        return Some((*data.get(pos + 1)? as usize, 2));
    }
    if first == 0x82 {
        let hi = *data.get(pos + 1)? as usize;
        let lo = *data.get(pos + 2)? as usize;
        return Some(((hi << 8) | lo, 3));
    }
    None
}

/// Monta `tag || len || value` (suporta valor até 65535).
pub(crate) fn tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + 3 + value.len());
    out.extend_from_slice(tag);
    if value.len() < 0x80 {
        out.push(value.len() as u8);
    } else if value.len() <= 0xFF {
        out.push(0x81);
        out.push(value.len() as u8);
    } else {
        out.push(0x82);
        out.push((value.len() >> 8) as u8);
        out.push((value.len() & 0xFF) as u8);
    }
    out.extend_from_slice(value);
    out
}

/// Extrai a tag do objeto de um GET DATA (`5C <len> <tag>`); `None` = malformado.
pub(crate) fn parse_get_tag(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 2 || data[0] != 0x5C {
        return None;
    }
    let len = data[1] as usize;
    if data.len() < 2 + len {
        return None;
    }
    Some(&data[2..2 + len])
}

/// Extrai o cert de um PUT DATA (`5C 03 5F C1 05 53 <len> <bytes>`, exato).
/// `None` = malformado (teto de tamanho checado no handler, `67 00`).
pub(crate) fn parse_put_cert(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 8 || data[0] != 0x5C || data[1] != 0x03 || data[5] != 0x53 {
        return None;
    }
    if data[2..5] != PIV_TAG_X509_CERT {
        return None;
    }
    let (len, lb) = read_len(data, 6)?;
    let start = 6 + lb;
    let end = start.checked_add(len)?;
    if end != data.len() {
        return None;
    }
    Some(&data[start..end])
}

/// Extrai o byte de algoritmo (`80`) do template `AC` do GENERATE.
/// `None` = malformado ou sem `80`.
pub(crate) fn parse_gen_alg(data: &[u8]) -> Option<u8> {
    if data.first() != Some(&0xAC) {
        return None;
    }
    let (ilen, lb) = read_len(data, 1)?;
    let start = 1 + lb;
    let inner = data.get(start..start.checked_add(ilen)?)?;
    let mut pos = 0;
    while pos + 2 <= inner.len() {
        let tag = inner[pos];
        let (llen, lb2) = read_len(inner, pos + 1)?;
        let vstart = pos + 1 + lb2;
        let vend = vstart.checked_add(llen)?;
        if vend > inner.len() {
            return None;
        }
        if tag == 0x80 && llen == 1 {
            return Some(inner[vstart]);
        }
        pos = vend;
    }
    None
}

/// Extrai o witness (`7C <len> <bytes>`, exato) do GENERAL AUTHENTICATE.
/// `None` = malformado.
pub(crate) fn parse_auth_witness(data: &[u8]) -> Option<&[u8]> {
    if data.first() != Some(&0x7C) {
        return None;
    }
    let (len, lb) = read_len(data, 1)?;
    let start = 1 + lb;
    let end = start.checked_add(len)?;
    if end != data.len() {
        return None;
    }
    Some(&data[start..end])
}
