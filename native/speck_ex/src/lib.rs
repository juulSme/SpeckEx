use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit, KeyIvInit, StreamCipher, Array};
use rustler::{Env, Error, ResourceArc, Binary, OwnedBinary};
use speck_cipher::{
    Speck128_128, Speck128_192, Speck128_256, Speck32_64, Speck48_72, Speck48_96, Speck64_128,
    Speck64_96, Speck96_144, Speck96_96,
};

// Resource wrapper
struct SpeckCipher<T>(T);

// Helper functions for block cipher operations
fn init<T: KeyInit>(key: &[u8]) -> Result<SpeckCipher<T>, Error> {
    T::new_from_slice(key).map_err(|_| Error::BadArg).map(SpeckCipher)
}

fn encrypt<'a, T: BlockCipherEncrypt>(env: Env<'a>, cipher: &SpeckCipher<T>, data: Binary) -> Result<Binary<'a>, Error> {
    let mut owned = OwnedBinary::new(data.len()).ok_or(Error::Atom("allocation_failed"))?;
    owned.as_mut_slice().copy_from_slice(data.as_slice());
    let block = <&mut Array<u8, _>>::try_from(owned.as_mut_slice()).map_err(|_| Error::BadArg)?;
    cipher.0.encrypt_block(block);
    Ok(owned.release(env))
}

fn decrypt<'a, T: BlockCipherDecrypt>(env: Env<'a>, cipher: &SpeckCipher<T>, data: Binary) -> Result<Binary<'a>, Error> {
    let mut owned = OwnedBinary::new(data.len()).ok_or(Error::Atom("allocation_failed"))?;
    owned.as_mut_slice().copy_from_slice(data.as_slice());
    let block = <&mut Array<u8, _>>::try_from(owned.as_mut_slice()).map_err(|_| Error::BadArg)?;
    cipher.0.decrypt_block(block);
    Ok(owned.release(env))
}

// Helper functions for CTR mode using ctr crate
fn ctr_encrypt_std<'a, C>(env: Env<'a>, key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Binary<'a>, Error>
where
    C: KeyIvInit + StreamCipher,
{
    let mut ctr = C::new(
        <&cipher::Array<u8, _>>::try_from(key).map_err(|_| Error::BadArg)?,
        <&cipher::Array<u8, _>>::try_from(nonce).map_err(|_| Error::BadArg)?
    );
    
    let mut owned = OwnedBinary::new(data.len()).ok_or(Error::Atom("allocation_failed"))?;
    owned.as_mut_slice().copy_from_slice(data);
    ctr.apply_keystream(owned.as_mut_slice());
    
    Ok(owned.release(env))
}

fn ctr_decrypt_std<'a, C>(env: Env<'a>, key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Binary<'a>, Error>
where
    C: KeyIvInit + StreamCipher,
{
    // CTR mode: encryption and decryption are the same
    ctr_encrypt_std::<C>(env, key, nonce, data)
}

// Macro to generate block cipher NIFs
macro_rules! impl_speck {
    ($name_init:ident, $name_encrypt:ident, $name_decrypt:ident, $cipher_type:ty) => {
        #[rustler::nif]
        fn $name_init(k: Binary) -> Result<ResourceArc<SpeckCipher<$cipher_type>>, Error> {
            Ok(ResourceArc::new(init(k.as_slice())?))
        }

        #[rustler::nif]
        fn $name_encrypt<'a>(env: Env<'a>, d: Binary, r: ResourceArc<SpeckCipher<$cipher_type>>) -> Result<Binary<'a>, Error> {
            encrypt(env, &r, d)
        }

        #[rustler::nif]
        fn $name_decrypt<'a>(env: Env<'a>, d: Binary, r: ResourceArc<SpeckCipher<$cipher_type>>) -> Result<Binary<'a>, Error> {
            decrypt(env, &r, d)
        }
    };
}

// Macro to generate CTR mode NIFs using the ctr crate
macro_rules! impl_speck_ctr {
    ($name_encrypt:ident, $name_decrypt:ident, $ctr_type:ty) => {
        #[rustler::nif]
        fn $name_encrypt<'a>(env: Env<'a>, key: Binary, nonce: Binary, data: Binary) -> Result<Binary<'a>, Error> {
            ctr_encrypt_std::<$ctr_type>(env, key.as_slice(), nonce.as_slice(), data.as_slice())
        }

        #[rustler::nif]
        fn $name_decrypt<'a>(env: Env<'a>, key: Binary, nonce: Binary, data: Binary) -> Result<Binary<'a>, Error> {
            ctr_decrypt_std::<$ctr_type>(env, key.as_slice(), nonce.as_slice(), data.as_slice())
        }
    };
}

// Generate block cipher NIFs for all variants
impl_speck!(speck32_64_init, speck32_64_encrypt, speck32_64_decrypt, Speck32_64);
impl_speck!(speck48_72_init, speck48_72_encrypt, speck48_72_decrypt, Speck48_72);
impl_speck!(speck48_96_init, speck48_96_encrypt, speck48_96_decrypt, Speck48_96);
impl_speck!(speck64_96_init, speck64_96_encrypt, speck64_96_decrypt, Speck64_96);
impl_speck!(speck64_128_init, speck64_128_encrypt, speck64_128_decrypt, Speck64_128);
impl_speck!(speck96_96_init, speck96_96_encrypt, speck96_96_decrypt, Speck96_96);
impl_speck!(speck96_144_init, speck96_144_encrypt, speck96_144_decrypt, Speck96_144);
impl_speck!(speck128_128_init, speck128_128_encrypt, speck128_128_decrypt, Speck128_128);
impl_speck!(speck128_192_init, speck128_192_encrypt, speck128_192_decrypt, Speck128_192);
impl_speck!(speck128_256_init, speck128_256_encrypt, speck128_256_decrypt, Speck128_256);

// Generate CTR mode NIFs - only for standard block sizes (32, 64, 128 bits)
impl_speck_ctr!(speck32_64_ctr_encrypt, speck32_64_ctr_decrypt, ctr::Ctr32BE<Speck32_64>);
impl_speck_ctr!(speck64_96_ctr_encrypt, speck64_96_ctr_decrypt, ctr::Ctr64BE<Speck64_96>);
impl_speck_ctr!(speck64_128_ctr_encrypt, speck64_128_ctr_decrypt, ctr::Ctr64BE<Speck64_128>);
impl_speck_ctr!(speck128_128_ctr_encrypt, speck128_128_ctr_decrypt, ctr::Ctr128BE<Speck128_128>);
impl_speck_ctr!(speck128_192_ctr_encrypt, speck128_192_ctr_decrypt, ctr::Ctr128BE<Speck128_192>);
impl_speck_ctr!(speck128_256_ctr_encrypt, speck128_256_ctr_decrypt, ctr::Ctr128BE<Speck128_256>);

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
