use std::cmp::Ordering;

use librypt_hash::HashFn;
use librypt_mac::{Mac, MacFn};

/// Hash-based Message Authentication Code Algorithm.
pub struct Hmac<
    const BLOCK_SIZE: usize,
    const OUTPUT_SIZE: usize,
    H: HashFn<BLOCK_SIZE, OUTPUT_SIZE>,
> {
    hasher: H,
    i_key_pad: [u8; BLOCK_SIZE],
    o_key_pad: [u8; BLOCK_SIZE],
}

impl<const BLOCK_SIZE: usize, const OUTPUT_SIZE: usize, H: HashFn<BLOCK_SIZE, OUTPUT_SIZE>>
    MacFn<OUTPUT_SIZE> for Hmac<BLOCK_SIZE, OUTPUT_SIZE, H>
{
    fn new(secret: &[u8]) -> Self {
        // TODO: Zero this out so its not just left in memory.
        let mut block_sized_key = [0u8; BLOCK_SIZE];

        // adjust secret size
        match secret.len().cmp(&BLOCK_SIZE) {
            // hash secret
            Ordering::Greater => {
                let hash = H::hash(secret);

                block_sized_key[0..hash.len()].copy_from_slice(&hash);
            }
            // pad secret
            Ordering::Less | Ordering::Equal => {
                block_sized_key[0..secret.len()].copy_from_slice(secret);
            }
        }

        let mut i_key_pad = [0u8; BLOCK_SIZE];
        let mut o_key_pad = [0u8; BLOCK_SIZE];

        for i in 0..block_sized_key.len() {
            i_key_pad[i] = block_sized_key[i] ^ 0x36;
        }

        for i in 0..block_sized_key.len() {
            o_key_pad[i] = block_sized_key[i] ^ 0x5c;
        }

        let mut hasher = H::new();

        hasher.update(&i_key_pad);

        Self {
            hasher,
            i_key_pad,
            o_key_pad,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(mut self) -> Mac<OUTPUT_SIZE> {
        let hash = self.hasher.finalize_reset();

        self.hasher.update(&self.o_key_pad);
        self.hasher.update(&hash);

        self.hasher.finalize()
    }

    fn finalize_reset(&mut self) -> Mac<OUTPUT_SIZE> {
        let hash = self.hasher.finalize_reset();

        self.hasher.update(&self.o_key_pad);
        self.hasher.update(&hash);

        let mac = self.hasher.finalize_reset();

        self.hasher.update(&self.i_key_pad);

        mac
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex::ToHex;
    use librypt_hash_md5::Md5;

    #[test]
    fn test_hmac() {
        let mac = Hmac::<64, 16, Md5>::mac(b"Hello, world!", b"test");

        if cfg!(target_endian = "big") {
            println!("Big Endian");
        } else {
            println!("Little Endian");
        }

        assert_eq!(
            mac.encode_hex::<String>(),
            "5286559abc8deaa260e8335499b2f6da"
        );
    }
}
