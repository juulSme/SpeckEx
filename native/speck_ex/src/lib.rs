use rustler::{Encoder, Env, Error, ResourceArc, Term};
use cipher::{BlockCipherEncrypt, BlockCipherDecrypt, KeyInit};
// RustCrypto speck-cipher types
type Speck64 = speck_cipher::Speck64_128;
type Speck96 = speck_cipher::Speck96_144;
type Speck128 = speck_cipher::Speck128_256;

mod atoms {
    rustler::atoms! {
        ok,
        error,
        speck64_128,
        speck96_144,
        speck128_256,
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum SpeckMode {
    Speck64_128,  // 32-bit words, 4 words (2 block, 2 key), 27 rounds
    Speck96_144,  // 48-bit words (emulated with u64), 3 block/3 key words, 28 rounds
    Speck128_256, // 64-bit words, 2 block/4 key words, 34 rounds
}

impl SpeckMode {
    fn block_size(&self) -> usize {
        match self {
            SpeckMode::Speck64_128 => 8,   // 64 bits = 8 bytes
            SpeckMode::Speck96_144 => 12,  // 96 bits = 12 bytes
            SpeckMode::Speck128_256 => 16, // 128 bits = 16 bytes
        }
    }

    fn key_size(&self) -> usize {
        match self {
            SpeckMode::Speck64_128 => 16,  // 128 bits = 16 bytes
            SpeckMode::Speck96_144 => 18,  // 144 bits = 18 bytes
            SpeckMode::Speck128_256 => 32, // 256 bits = 32 bytes
        }
    }
}

enum SpeckCipher {
    Speck64(Speck64),
    Speck96(Speck96),
    Speck128(Speck128),
}

struct SpeckState {
    mode: SpeckMode,
    cipher: SpeckCipher,
}

impl SpeckState {
    fn new(key: &[u8], mode: SpeckMode) -> Result<Self, String> {
        if key.len() != mode.key_size() {
            return Err(format!(
                "Invalid key size: expected {} bytes, got {}",
                mode.key_size(),
                key.len()
            ));
        }

        let cipher = match mode {
            SpeckMode::Speck64_128 => {
                let key_array = key.try_into().unwrap();
                SpeckCipher::Speck64(Speck64::new(key_array))
            }
            SpeckMode::Speck96_144 => {
                let key_array = key.try_into().unwrap();
                SpeckCipher::Speck96(Speck96::new(key_array))
            }
            SpeckMode::Speck128_256 => {
                let key_array = key.try_into().unwrap();
                SpeckCipher::Speck128(Speck128::new(key_array))
            }
        };

        Ok(SpeckState { mode, cipher })
    }

    // Encrypt a single block
    fn encrypt_block(&self, block: &[u8]) -> Result<Vec<u8>, String> {
        if block.len() != self.mode.block_size() {
            return Err(format!(
                "Invalid block size: expected {} bytes, got {}",
                self.mode.block_size(),
                block.len()
            ));
        }

        let mut result = block.to_vec();
        
        match &self.cipher {
            SpeckCipher::Speck64(cipher) => {
                let block_array = result.as_mut_slice().try_into().unwrap();
                cipher.encrypt_block(block_array);
            }
            SpeckCipher::Speck96(cipher) => {
                let block_array = result.as_mut_slice().try_into().unwrap();
                cipher.encrypt_block(block_array);
            }
            SpeckCipher::Speck128(cipher) => {
                let block_array = result.as_mut_slice().try_into().unwrap();
                cipher.encrypt_block(block_array);
            }
        }

        Ok(result)
    }

    // Decrypt a single block
    fn decrypt_block(&self, block: &[u8]) -> Result<Vec<u8>, String> {
        if block.len() != self.mode.block_size() {
            return Err(format!(
                "Invalid block size: expected {} bytes, got {}",
                self.mode.block_size(),
                block.len()
            ));
        }

        let mut result = block.to_vec();
        
        match &self.cipher {
            SpeckCipher::Speck64(cipher) => {
                let block_array = result.as_mut_slice().try_into().unwrap();
                cipher.decrypt_block(block_array);
            }
            SpeckCipher::Speck96(cipher) => {
                let block_array = result.as_mut_slice().try_into().unwrap();
                cipher.decrypt_block(block_array);
            }
            SpeckCipher::Speck128(cipher) => {
                let block_array = result.as_mut_slice().try_into().unwrap();
                cipher.decrypt_block(block_array);
            }
        }

        Ok(result)
    }

    // CTR mode encryption/decryption (symmetric operation)
    fn ctr_crypt(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
        let block_size = self.mode.block_size();
        
        if iv.len() != block_size {
            return Err(format!(
                "Invalid IV size: expected {} bytes, got {}",
                block_size,
                iv.len()
            ));
        }

        let mut result = Vec::with_capacity(data.len());
        let mut counter = iv.to_vec();
        
        for chunk in data.chunks(block_size) {
            // Encrypt the counter
            let keystream = self.encrypt_block(&counter)?;
            
            // XOR with data
            for (i, &byte) in chunk.iter().enumerate() {
                result.push(byte ^ keystream[i]);
            }
            
            // Increment counter (little-endian)
            let mut carry = 1u16;
            for byte in counter.iter_mut() {
                let sum = *byte as u16 + carry;
                *byte = sum as u8;
                carry = sum >> 8;
                if carry == 0 {
                    break;
                }
            }
        }

        Ok(result)
    }
}

// Rustler resource definition
pub struct SpeckResource {
    state: SpeckState,
}

fn load(env: Env, _: Term) -> bool {
    #[allow(non_local_definitions)]
    {
        let _ = rustler::resource!(SpeckResource, env);
    }
    true
}

// NIF: Initialize cipher with key and mode
#[rustler::nif]
fn init_nif(key: rustler::Binary, mode_atom: Term) -> Result<ResourceArc<SpeckResource>, Error> {
    let mode = if mode_atom == atoms::speck64_128().encode(mode_atom.get_env()) {
        SpeckMode::Speck64_128
    } else if mode_atom == atoms::speck96_144().encode(mode_atom.get_env()) {
        SpeckMode::Speck96_144
    } else if mode_atom == atoms::speck128_256().encode(mode_atom.get_env()) {
        SpeckMode::Speck128_256
    } else {
        return Err(Error::BadArg);
    };

    match SpeckState::new(key.as_slice(), mode) {
        Ok(state) => {
            let resource = ResourceArc::new(SpeckResource {
                state,
            });
            Ok(resource)
        }
        Err(_) => Err(Error::BadArg),
    }
}

// NIF: Encrypt or decrypt a single block
#[rustler::nif]
fn block_crypt_nif<'a>(
    env: Env<'a>,
    block: rustler::Binary,
    resource: ResourceArc<SpeckResource>,
    decrypt: bool,
) -> Result<rustler::Binary<'a>, Error> {
    let result = if decrypt {
        resource.state.decrypt_block(block.as_slice())
    } else {
        resource.state.encrypt_block(block.as_slice())
    };

    match result {
        Ok(data) => {
            let mut binary = rustler::OwnedBinary::new(data.len()).unwrap();
            binary.as_mut_slice().copy_from_slice(&data);
            Ok(binary.release(env).into())
        }
        Err(_) => Err(Error::BadArg),
    }
}

// NIF: CTR mode encryption/decryption
#[rustler::nif]
fn ctr_crypt_nif<'a>(
    env: Env<'a>,
    data: rustler::Binary,
    resource: ResourceArc<SpeckResource>,
    iv: rustler::Binary,
) -> Result<rustler::Binary<'a>, Error> {
    match resource.state.ctr_crypt(data.as_slice(), iv.as_slice()) {
        Ok(result) => {
            let mut binary = rustler::OwnedBinary::new(result.len()).unwrap();
            binary.as_mut_slice().copy_from_slice(&result);
            Ok(binary.release(env).into())
        }
        Err(_) => Err(Error::BadArg),
    }
}

rustler::init!("Elixir.SpeckEx.Native", load = load);
