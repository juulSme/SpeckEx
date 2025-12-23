use cipher::generic_array::GenericArray;
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use poly1305::{universal_hash::UniversalHash, Poly1305};
use rustler::{Binary, Env, Error, OwnedBinary, ResourceArc};
use speck_cipher::{
    Speck128_128, Speck128_192, Speck128_256, Speck32_64, Speck48_72, Speck48_96, Speck64_128,
    Speck64_96, Speck96_144, Speck96_96,
};

// Resource wrapper
struct SpeckCipher<T>(T);

// Helper functions for block cipher operations
fn init<T: KeyInit>(key: &[u8]) -> Result<SpeckCipher<T>, Error> {
    T::new_from_slice(key)
        .map_err(|_| Error::BadArg)
        .map(SpeckCipher)
}

fn encrypt<'a, T: BlockEncrypt>(
    env: Env<'a>,
    cipher: &SpeckCipher<T>,
    data: Binary,
) -> Result<Binary<'a>, Error> {
    let mut owned = OwnedBinary::new(data.len()).ok_or(Error::Atom("allocation_failed"))?;
    owned.as_mut_slice().copy_from_slice(data.as_slice());
    let block = GenericArray::from_mut_slice(owned.as_mut_slice());
    cipher.0.encrypt_block(block);
    Ok(owned.release(env))
}

fn decrypt<'a, T: BlockDecrypt>(
    env: Env<'a>,
    cipher: &SpeckCipher<T>,
    data: Binary,
) -> Result<Binary<'a>, Error> {
    let mut owned = OwnedBinary::new(data.len()).ok_or(Error::Atom("allocation_failed"))?;
    owned.as_mut_slice().copy_from_slice(data.as_slice());
    let block = GenericArray::from_mut_slice(owned.as_mut_slice());
    cipher.0.decrypt_block(block);
    Ok(owned.release(env))
}

// Macro to generate block cipher NIFs
macro_rules! impl_speck {
    ($name_init:ident, $name_encrypt:ident, $name_decrypt:ident, $cipher_type:ty) => {
        #[rustler::nif]
        fn $name_init(k: Binary) -> Result<ResourceArc<SpeckCipher<$cipher_type>>, Error> {
            Ok(ResourceArc::new(init(k.as_slice())?))
        }

        #[rustler::nif]
        fn $name_encrypt<'a>(
            env: Env<'a>,
            d: Binary,
            r: ResourceArc<SpeckCipher<$cipher_type>>,
        ) -> Result<Binary<'a>, Error> {
            encrypt(env, &r, d)
        }

        #[rustler::nif]
        fn $name_decrypt<'a>(
            env: Env<'a>,
            d: Binary,
            r: ResourceArc<SpeckCipher<$cipher_type>>,
        ) -> Result<Binary<'a>, Error> {
            decrypt(env, &r, d)
        }
    };
}

// Generate block cipher NIFs for all variants
impl_speck!(
    speck32_64_init,
    speck32_64_encrypt,
    speck32_64_decrypt,
    Speck32_64
);
impl_speck!(
    speck48_72_init,
    speck48_72_encrypt,
    speck48_72_decrypt,
    Speck48_72
);
impl_speck!(
    speck48_96_init,
    speck48_96_encrypt,
    speck48_96_decrypt,
    Speck48_96
);
impl_speck!(
    speck64_96_init,
    speck64_96_encrypt,
    speck64_96_decrypt,
    Speck64_96
);
impl_speck!(
    speck64_128_init,
    speck64_128_encrypt,
    speck64_128_decrypt,
    Speck64_128
);
impl_speck!(
    speck96_96_init,
    speck96_96_encrypt,
    speck96_96_decrypt,
    Speck96_96
);
impl_speck!(
    speck96_144_init,
    speck96_144_encrypt,
    speck96_144_decrypt,
    Speck96_144
);
impl_speck!(
    speck128_128_init,
    speck128_128_encrypt,
    speck128_128_decrypt,
    Speck128_128
);
impl_speck!(
    speck128_192_init,
    speck128_192_encrypt,
    speck128_192_decrypt,
    Speck128_192
);
impl_speck!(
    speck128_256_init,
    speck128_256_encrypt,
    speck128_256_decrypt,
    Speck128_256
);

// Helper functions for CTR mode using ctr crate
fn ctr_crypt_std<'a, C>(
    env: Env<'a>,
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
) -> Result<Binary<'a>, Error>
where
    C: KeyIvInit + StreamCipher,
{
    let mut ctr = C::new(
        GenericArray::from_slice(key),
        GenericArray::from_slice(nonce),
    );

    let mut owned = OwnedBinary::new(data.len()).ok_or(Error::Atom("allocation_failed"))?;
    owned.as_mut_slice().copy_from_slice(data);
    ctr.apply_keystream(owned.as_mut_slice());

    Ok(owned.release(env))
}

// Macro to generate CTR mode NIFs using the ctr crate
macro_rules! impl_speck_ctr {
    ($name_crypt:ident, $ctr_type:ty) => {
        #[rustler::nif]
        fn $name_crypt<'a>(
            env: Env<'a>,
            key: Binary,
            nonce: Binary,
            data: Binary,
        ) -> Result<Binary<'a>, Error> {
            ctr_crypt_std::<$ctr_type>(env, key.as_slice(), nonce.as_slice(), data.as_slice())
        }
    };
}

// Generate CTR mode NIFs - only for standard block sizes (32, 64, 128 bits)
impl_speck_ctr!(speck32_64_ctr_crypt, ctr::Ctr32BE<Speck32_64>);
impl_speck_ctr!(speck64_96_ctr_crypt, ctr::Ctr64BE<Speck64_96>);
impl_speck_ctr!(speck64_128_ctr_crypt, ctr::Ctr64BE<Speck64_128>);
impl_speck_ctr!(speck128_128_ctr_crypt, ctr::Ctr128BE<Speck128_128>);
impl_speck_ctr!(speck128_192_ctr_crypt, ctr::Ctr128BE<Speck128_192>);
impl_speck_ctr!(speck128_256_ctr_crypt, ctr::Ctr128BE<Speck128_256>);

// Poly1305 AEAD helper functions
fn compute_poly1305_tag(poly_key: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<[u8; 16], Error> {
    // Initialize Poly1305 with derived key
    let mut mac = Poly1305::new_from_slice(poly_key).map_err(|_| Error::BadArg)?;

    // Compute MAC over: AAD || pad || ciphertext || pad || lengths
    mac.update_padded(aad);
    mac.update_padded(ciphertext);

    // Add lengths as 8-byte little-endian integers
    let mut lengths = [0u8; 16];
    lengths[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lengths[8..16].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    mac.update_padded(&lengths);

    Ok(mac.finalize().into())
}

fn speck_poly1305_encrypt_impl<'a, C>(
    env: Env<'a>,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Binary<'a>, Binary<'a>), Error>
where
    C: KeyIvInit + StreamCipher,
{
    // Initialize CTR mode
    let mut ctr = C::new(
        GenericArray::from_slice(key),
        GenericArray::from_slice(nonce),
    );

    // Derive Poly1305 key (first 32 bytes of keystream)
    let mut p1305_key = [0u8; 32];
    ctr.apply_keystream(&mut p1305_key);

    // Encrypt plaintext
    let mut ciphertext_owned =
        OwnedBinary::new(plaintext.len()).ok_or(Error::Atom("allocation_failed"))?;
    ciphertext_owned.as_mut_slice().copy_from_slice(plaintext);
    ctr.apply_keystream(ciphertext_owned.as_mut_slice());

    // Compute MAC
    let tag = compute_poly1305_tag(&p1305_key, aad, ciphertext_owned.as_slice())?;

    let mut tag_owned = OwnedBinary::new(16).ok_or(Error::Atom("allocation_failed"))?;
    tag_owned.as_mut_slice().copy_from_slice(&tag);

    Ok((ciphertext_owned.release(env), tag_owned.release(env)))
}

fn speck_poly1305_decrypt_impl<'a, C>(
    env: Env<'a>,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Result<Binary<'a>, Error>
where
    C: KeyIvInit + StreamCipher,
{
    // Initialize CTR mode
    let mut ctr = C::new(
        GenericArray::from_slice(key),
        GenericArray::from_slice(nonce),
    );

    // Derive Poly1305 key (first 32 bytes of keystream)
    let mut p1305_key = [0u8; 32];
    ctr.apply_keystream(&mut p1305_key);

    // Verify MAC
    let expected_tag = compute_poly1305_tag(&p1305_key, aad, ciphertext)?;

    // Constant-time comparison
    use subtle::ConstantTimeEq;
    if !bool::from(expected_tag.ct_eq(tag)) {
        return Err(Error::Atom("authentication_failed"));
    }

    // Decrypt ciphertext
    let mut plaintext_owned =
        OwnedBinary::new(ciphertext.len()).ok_or(Error::Atom("allocation_failed"))?;
    plaintext_owned.as_mut_slice().copy_from_slice(ciphertext);
    ctr.apply_keystream(plaintext_owned.as_mut_slice());

    Ok(plaintext_owned.release(env))
}

// Macro to generate Poly1305 AEAD NIFs
macro_rules! impl_speck_poly1305 {
    ($name_encrypt:ident, $name_decrypt:ident, $ctr_type:ty) => {
        #[rustler::nif]
        fn $name_encrypt<'a>(
            env: Env<'a>,
            key: Binary,
            nonce: Binary,
            plaintext: Binary,
            aad: Binary,
        ) -> Result<(Binary<'a>, Binary<'a>), Error> {
            speck_poly1305_encrypt_impl::<$ctr_type>(
                env,
                key.as_slice(),
                nonce.as_slice(),
                plaintext.as_slice(),
                aad.as_slice(),
            )
        }

        #[rustler::nif]
        fn $name_decrypt<'a>(
            env: Env<'a>,
            key: Binary,
            nonce: Binary,
            ciphertext: Binary,
            tag: Binary,
            aad: Binary,
        ) -> Result<Binary<'a>, Error> {
            speck_poly1305_decrypt_impl::<$ctr_type>(
                env,
                key.as_slice(),
                nonce.as_slice(),
                ciphertext.as_slice(),
                tag.as_slice(),
                aad.as_slice(),
            )
        }
    };
}

// Generate Poly1305 AEAD NIFs for CTR-compatible variants
impl_speck_poly1305!(
    speck32_64_poly1305_encrypt,
    speck32_64_poly1305_decrypt,
    ctr::Ctr32BE<Speck32_64>
);
impl_speck_poly1305!(
    speck64_96_poly1305_encrypt,
    speck64_96_poly1305_decrypt,
    ctr::Ctr64BE<Speck64_96>
);
impl_speck_poly1305!(
    speck64_128_poly1305_encrypt,
    speck64_128_poly1305_decrypt,
    ctr::Ctr64BE<Speck64_128>
);
impl_speck_poly1305!(
    speck128_128_poly1305_encrypt,
    speck128_128_poly1305_decrypt,
    ctr::Ctr128BE<Speck128_128>
);
impl_speck_poly1305!(
    speck128_192_poly1305_encrypt,
    speck128_192_poly1305_decrypt,
    ctr::Ctr128BE<Speck128_192>
);
impl_speck_poly1305!(
    speck128_256_poly1305_encrypt,
    speck128_256_poly1305_decrypt,
    ctr::Ctr128BE<Speck128_256>
);

#[allow(non_local_definitions)]
fn on_load(env: Env, _info: rustler::Term) -> bool {
    let _ = rustler::resource!(SpeckCipher<Speck32_64>, env);
    let _ = rustler::resource!(SpeckCipher<Speck48_72>, env);
    let _ = rustler::resource!(SpeckCipher<Speck48_96>, env);
    let _ = rustler::resource!(SpeckCipher<Speck64_96>, env);
    let _ = rustler::resource!(SpeckCipher<Speck64_128>, env);
    let _ = rustler::resource!(SpeckCipher<Speck96_96>, env);
    let _ = rustler::resource!(SpeckCipher<Speck96_144>, env);
    let _ = rustler::resource!(SpeckCipher<Speck128_128>, env);
    let _ = rustler::resource!(SpeckCipher<Speck128_192>, env);
    let _ = rustler::resource!(SpeckCipher<Speck128_256>, env);
    true
}

rustler::init!("Elixir.SpeckEx.Native", load = on_load);
