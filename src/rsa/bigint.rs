use super::{Error, RsaPublicKey};

pub(crate) type Number = [u64; 128];

pub(crate) fn word(words: &[u64], i: usize) -> u64 {
    words.get(i).copied().unwrap_or(0)
}

fn put(words: &mut [u64], i: usize, value: u64) -> Result<(), Error> {
    *words.get_mut(i).ok_or(Error::Verification)? = value;
    Ok(())
}

pub(crate) fn decode(bytes: &[u8]) -> Result<Number, Error> {
    if bytes.len() > 1024 {
        return Err(Error::Verification);
    }
    let mut result = [0; 128];
    for (i, byte) in bytes.iter().rev().enumerate() {
        let slot = result.get_mut(i / 8).ok_or(Error::Verification)?;
        *slot |= u64::from(*byte) << ((i % 8) * 8);
    }
    Ok(result)
}

pub(crate) fn encode(number: &Number, bytes: &mut [u8]) {
    for (i, byte) in bytes.iter_mut().rev().enumerate() {
        *byte = (word(number, i / 8) >> ((i % 8) * 8)) as u8;
    }
}

pub(crate) fn less(a: &Number, b: &Number, limbs: usize) -> bool {
    for i in (0..limbs).rev() {
        let left = word(a, i);
        let right = word(b, i);
        if left != right {
            return left < right;
        }
    }
    false
}

fn subtract(a: &mut Number, b: &Number, limbs: usize) -> Result<(), Error> {
    let mut borrow = false;
    for i in 0..limbs {
        let (value, first) = word(a, i).overflowing_sub(word(b, i));
        let (value, second) = value.overflowing_sub(u64::from(borrow));
        put(a, i, value)?;
        borrow = first || second;
    }
    Ok(())
}

pub(crate) fn inverse(low: u64) -> u64 {
    let mut inverse = 1u64;
    for _ in 0..6 {
        inverse = inverse.wrapping_mul(2u64.wrapping_sub(low.wrapping_mul(inverse)));
    }
    inverse.wrapping_neg()
}

pub(crate) fn r2(modulus: &Number, limbs: usize) -> Result<Number, Error> {
    let mut result = [0; 128];
    put(&mut result, 0, 1)?;
    // Repeated modular doubling produces R^2, where R = 2^(64 * limbs).
    for _ in 0..(128 * limbs) {
        let mut carry = 0;
        for i in 0..limbs {
            let value = word(&result, i);
            put(&mut result, i, (value << 1) | carry)?;
            carry = value >> 63;
        }
        if carry != 0 || !less(&result, modulus, limbs) {
            subtract(&mut result, modulus, limbs)?;
        }
    }
    Ok(result)
}

fn propagate(words: &mut [u64], mut i: usize, mut carry: u64) -> Result<(), Error> {
    while carry != 0 {
        let (value, overflow) = word(words, i).overflowing_add(carry);
        put(words, i, value)?;
        carry = u64::from(overflow);
        i += 1;
    }
    Ok(())
}

fn multiply(key: &RsaPublicKey, a: &Number, b: &Number) -> Result<Number, Error> {
    let limbs = key.limbs;
    let mut product = [0u64; 258];
    for i in 0..limbs {
        let mut carry = 0u64;
        for j in 0..limbs {
            let value = u128::from(word(a, i)) * u128::from(word(b, j))
                + u128::from(word(&product, i + j))
                + u128::from(carry);
            put(&mut product, i + j, value as u64)?;
            carry = (value >> 64) as u64;
        }
        propagate(&mut product, i + limbs, carry)?;
    }
    // REDC cancels one low limb per iteration using -n^-1 modulo 2^64.
    for i in 0..limbs {
        let factor = word(&product, i).wrapping_mul(key.inverse);
        let mut carry = 0u64;
        for j in 0..limbs {
            let value = u128::from(factor) * u128::from(word(&key.modulus, j))
                + u128::from(word(&product, i + j))
                + u128::from(carry);
            put(&mut product, i + j, value as u64)?;
            carry = (value >> 64) as u64;
        }
        propagate(&mut product, i + limbs, carry)?;
    }
    let mut result = [0; 128];
    for i in 0..limbs {
        put(&mut result, i, word(&product, i + limbs))?;
    }
    // Reduced inputs imply REDC < 2n, including a possible extra high limb.
    if word(&product, 2 * limbs) != 0 || !less(&result, &key.modulus, limbs) {
        subtract(&mut result, &key.modulus, limbs)?;
    }
    Ok(result)
}

pub(crate) fn exponentiate(key: &RsaPublicKey, signature: &Number) -> Result<Number, Error> {
    let base = multiply(key, signature, &key.r2)?;
    let mut result = base;
    for _ in 0..16 {
        result = multiply(key, &result, &result)?;
    }
    result = multiply(key, &result, &base)?;
    let mut one = [0; 128];
    put(&mut one, 0, 1)?;
    multiply(key, &result, &one)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn montgomery_matches_small_arithmetic() {
        for modulus in [3u64, 17, 65537, u64::MAX, u64::MAX - 58] {
            let mut n = [0; 128];
            n[0] = modulus;
            let key = RsaPublicKey {
                modulus: n,
                r2: r2(&n, 1).unwrap(),
                limbs: 1,
                bits: 64,
                inverse: inverse(modulus),
            };
            for value in [0, 1, 2, modulus / 2, modulus - 1] {
                let mut a = [0; 128];
                a[0] = value;
                let mut expected = u128::from(value);
                for _ in 0..16 {
                    expected = expected * expected % u128::from(modulus);
                }
                expected = expected * u128::from(value) % u128::from(modulus);
                assert_eq!(exponentiate(&key, &a).unwrap()[0], expected as u64);
            }
        }
    }
}
