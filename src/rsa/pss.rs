// Verify structure follows RustCrypto rsa (src/algorithms/pss.rs),
// MIT OR Apache-2.0, The RustCrypto Project Developers.

use super::Error;
use sha2::Digest;

pub(crate) fn verify<D: Digest>(
    digest: &[u8],
    encoded: &mut [u8],
    bits: usize,
) -> Result<(), Error> {
    let em_bits = bits.checked_sub(1).ok_or(Error::Verification)?;
    let em_len = em_bits.div_ceil(8);
    let leading = encoded
        .len()
        .checked_sub(em_len)
        .ok_or(Error::Verification)?;
    if encoded
        .get(..leading)
        .ok_or(Error::Verification)?
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(Error::Verification);
    }
    let em = encoded.get_mut(leading..).ok_or(Error::Verification)?;
    let h_len = <D as Digest>::output_size();
    if digest.len() != h_len || em_len < 2 * h_len + 2 || em.last() != Some(&0xbc) {
        return Err(Error::Verification);
    }
    let db_len = em_len - h_len - 1;
    let mut h = [0u8; 64];
    let h = h.get_mut(..h_len).ok_or(Error::Verification)?;
    for (dst, src) in h
        .iter_mut()
        .zip(em.get(db_len..db_len + h_len).ok_or(Error::Verification)?)
    {
        *dst = *src;
    }
    let db = em.get_mut(..db_len).ok_or(Error::Verification)?;
    let mask = 0xffu8 >> (8 * em_len - em_bits);
    if db.first().ok_or(Error::Verification)? & !mask != 0 {
        return Err(Error::Verification);
    }
    for (counter, chunk) in db.chunks_mut(h_len).enumerate() {
        let mut hash = D::new();
        hash.update(&*h);
        hash.update((counter as u32).to_be_bytes());
        let block = hash.finalize();
        for (byte, mask_byte) in chunk.iter_mut().zip(block.iter()) {
            *byte ^= *mask_byte;
        }
    }
    *db.first_mut().ok_or(Error::Verification)? &= mask;
    let separator = db_len - h_len - 1;
    if db
        .get(..separator)
        .ok_or(Error::Verification)?
        .iter()
        .any(|b| *b != 0)
        || db.get(separator) != Some(&1)
    {
        return Err(Error::Verification);
    }
    let mut hash = D::new();
    hash.update([0u8; 8]);
    hash.update(digest);
    hash.update(db.get(separator + 1..).ok_or(Error::Verification)?);
    let difference = hash
        .finalize()
        .iter()
        .zip(h.iter())
        .fold(0u8, |a, (b, c)| a | (b ^ c));
    if difference == 0 {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}
