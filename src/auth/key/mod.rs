use ring::aead::{seal_in_place, open_in_place, Algorithm, AES_256_GCM};
use ring::aead::{OpeningKey, SealingKey};
use ring::rand::{SecureRandom, SystemRandom};
use base64;

// Keep following in sync with ring configuration
static ALGO: &'static Algorithm = &AES_256_GCM;
const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

pub struct Key {
    open_key: OpeningKey,
    seal_key: SealingKey,
}

/// May generate master key via ```openssl rand -base64 32```
impl Key {
    /// Creates a new Key.
    pub fn new(master_key: Option<&str>) -> Result<Key, &'static str> {
        let mut base_key = [0u8; KEY_LEN];
        if let Some(k) = master_key {
            let rnd = base64::decode(k)
                .map_err(|_| "Master key base64 decode error.")?;
            if rnd.len() < KEY_LEN {
                return Err("Master key length too short.");
            }
            base_key.copy_from_slice(&rnd[..])
        } else {
            let mut rnd = [0u8; KEY_LEN];
            SystemRandom::new()
               .fill(&mut rnd)
               .map_err(|_| "Could NOT fill base_key with randomness")?;
            base_key.copy_from_slice(&rnd);
        }
        let open_key = OpeningKey::new(ALGO, &base_key)
            .map_err(|_| "opening key error")?;
        let seal_key = SealingKey::new(ALGO, &base_key)
            .map_err(|_| "sealing key creation error")?;
        Ok(Key{ open_key: open_key, seal_key: seal_key })
    }

    /// Given a clear `value` and an associated `key`, a nonce will be
    /// randomly generated and prepended to the encrypted value, and then
    /// both are Base64 encoded. If there is a problem, returns an `Err`
    /// with a string describing the issue.
    pub fn seal(&self, key: &str, value: &str) -> Result<String, &'static str> {
        // Create a vec to hold the [nonce/header | value | tag].
        let value = value.as_bytes();
        let tag = ALGO.tag_len();
        let mut output = vec![0; NONCE_LEN + value.len() + tag];

        // Use key as associated value to prevent swapping value between index_keys/key.
        let ad = key.as_bytes();

        // scope split of output into nonce and in_out; so later we can reuse output
        let output_len = {
            let (nonce, in_out) = output.split_at_mut(NONCE_LEN);
            // Randomly generate nonce.
            SystemRandom::new()
               .fill(nonce)
               .map_err(|_| "Could NOT fill nonce with randomness.")?;

            // Copy the value as input.
            in_out[..value.len()].copy_from_slice(value);

            // Perform the actual sealing operation and get the output length.
            seal_in_place(&(&self.seal_key), nonce, ad, in_out, tag)
                .map_err(|_| "in-place seal")?
        };

        // Base64 encode the nonce and encrypted value.
        Ok(base64::encode(&output[..(NONCE_LEN + output_len)]))
    }

    /// Given sealed `value` and an associated `key`, where the nonce is prepended
    /// to the original value and then both are Base64 encoded, verifies the
    /// sealed value and returns the decrypted value. If there is a problem,
    /// returns an `Err` with a string describing the issue.
    pub fn unseal(&self, key: &str, value: &str) -> Result<String, &'static str> {
        let mut value = base64::decode(value)
            .map_err(|_| "Invalid base64 value.")?;
        if value.len() <= NONCE_LEN {
            return Err("Length of decoded value is less then length of nonce");
        }

        let ad = key.as_bytes();
        let (nonce, sealed) = value.split_at_mut(NONCE_LEN);
        let unsealed = open_in_place(&(&self.open_key), nonce, ad, 0, sealed)
            .map_err(|_| "Invalid sealed key/nonce/ad/value.")?;

        ::std::str::from_utf8(unsealed)
            .map(|s| s.to_string())
            .map_err(|_| "Invalid unsealed UTF-8.")
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_unseal() {
        let master_key = "sVdCPIwy2URfikVQiBH1Z+Jz39mibRG7viq42oYapTA=";
        let data_key = "name";
        let data_value = "data";
        let test_key = Key::new(Some(master_key)).unwrap();
        let sealed_data_value = test_key.seal(data_key, data_value).unwrap();
        assert_eq!(data_value, test_key.unseal(data_key, &sealed_data_value[..]).unwrap())
    }
}

