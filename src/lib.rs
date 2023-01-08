use std::{cmp::Ordering, marker::PhantomData};

use librypt_hash::HashFn;
use librypt_mac::{Mac, MacFn};

/// Hash-based Message Authentication Code Algorithm.
pub struct Hmac<
    const BLOCK_SIZE: usize,
    const OUTPUT_SIZE: usize,
    H: HashFn<BLOCK_SIZE, OUTPUT_SIZE>,
>(PhantomData<H>);

impl<const BLOCK_SIZE: usize, const OUTPUT_SIZE: usize, H: HashFn<BLOCK_SIZE, OUTPUT_SIZE>>
    MacFn<OUTPUT_SIZE> for Hmac<BLOCK_SIZE, OUTPUT_SIZE, H>
{
    fn compute(msg: &[u8], secret: &[u8]) -> Mac<OUTPUT_SIZE> {
        // TODO: Zero this out so its not just left in memory.
        let mut block_sized_key = [0u8; BLOCK_SIZE];

        // adjust secret size
        match secret.len().cmp(&BLOCK_SIZE) {
            // hash secret
            Ordering::Greater => {
                let hash = H::hash(secret);

                for i in 0..hash.len() {
                    block_sized_key[i] = hash[i];
                }
            }
            // pad secret
            Ordering::Less | Ordering::Equal => {
                for i in 0..secret.len() {
                    block_sized_key[i] = secret[i];
                }
            }
        }

        let mut i_key_pad = [0u8; BLOCK_SIZE];
        let mut o_key_pad = [0u8; BLOCK_SIZE];

        for i in 0..block_sized_key.len() {
            i_key_pad[i] = block_sized_key[i] ^ 0x5c;
        }

        for i in 0..block_sized_key.len() {
            o_key_pad[i] = block_sized_key[i] ^ 0x36;
        }

        // compute final HMAC
        H::hash(
            [
                &o_key_pad,
                H::hash([&i_key_pad, msg].concat().as_ref()).as_ref(),
            ]
            .concat()
            .as_ref(),
        )
    }
}
