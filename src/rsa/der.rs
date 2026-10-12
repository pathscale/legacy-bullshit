use super::Error;

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, Error> {
        let (byte, rest) = self.0.split_first().ok_or(Error::Der)?;
        self.0 = rest;
        Ok(*byte)
    }

    fn value(&mut self, tag: u8) -> Result<&'a [u8], Error> {
        if self.byte()? != tag {
            return Err(Error::Der);
        }
        let first = self.byte()?;
        let length = if first < 128 {
            usize::from(first)
        } else {
            let count = usize::from(first & 127);
            if count == 0 || count > core::mem::size_of::<usize>() {
                return Err(Error::Der);
            }
            let mut length = 0usize;
            for i in 0..count {
                let byte = self.byte()?;
                if i == 0 && byte == 0 {
                    return Err(Error::Der);
                }
                length = length
                    .checked_mul(256)
                    .and_then(|n| n.checked_add(usize::from(byte)))
                    .ok_or(Error::Der)?;
            }
            if length < 128 {
                return Err(Error::Der);
            }
            length
        };
        let value = self.0.get(..length).ok_or(Error::Der)?;
        self.0 = self.0.get(length..).ok_or(Error::Der)?;
        Ok(value)
    }

    fn end(self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Der)
        }
    }

    fn integer(&mut self) -> Result<&'a [u8], Error> {
        let value = self.value(2)?;
        let (first, rest) = value.split_first().ok_or(Error::Der)?;
        if first & 128 != 0 {
            return Err(Error::Der);
        }
        if *first == 0 {
            if rest.first().is_none_or(|byte| byte & 128 == 0) {
                return Err(Error::Der);
            }
            Ok(rest)
        } else {
            Ok(value)
        }
    }
}

pub(crate) fn public_key(input: &[u8]) -> Result<&[u8], Error> {
    let mut outer = Reader(input);
    let mut inner = Reader(outer.value(0x30)?);
    outer.end()?;
    let modulus = inner.integer()?;
    let exponent = inner.integer()?;
    inner.end()?;
    if exponent != [1, 0, 1] {
        return Err(Error::Key);
    }
    Ok(modulus)
}

pub(crate) fn spki(input: &[u8]) -> Result<&[u8], Error> {
    let mut outer = Reader(input);
    let mut inner = Reader(outer.value(0x30)?);
    outer.end()?;
    let mut algorithm = Reader(inner.value(0x30)?);
    if algorithm.value(6)? != [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1]
        || !algorithm.value(5)?.is_empty()
    {
        return Err(Error::Der);
    }
    algorithm.end()?;
    let bits = inner.value(3)?;
    inner.end()?;
    let (unused, key) = bits.split_first().ok_or(Error::Der)?;
    if *unused != 0 {
        return Err(Error::Der);
    }
    Ok(key)
}
