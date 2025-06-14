#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use tokio_util::codec::Decoder;

// We need to make SimpleLdapCodec public in the module
// For now, let's use the same module structure
use yamldap::ldap::SimpleLdapCodec;

fuzz_target!(|data: &[u8]| {
    // Create a BytesMut buffer from the fuzz input
    let mut buf = BytesMut::from(data);
    
    // Create a decoder instance
    let mut codec = SimpleLdapCodec;
    
    // Try to decode the data
    // The decoder should handle any malformed input gracefully
    match codec.decode(&mut buf) {
        Ok(Some(_msg)) => {
            // Successfully decoded a message
        }
        Ok(None) => {
            // Not enough data to decode a complete message
        }
        Err(_e) => {
            // Decoding error - this is expected for malformed input
            // The important thing is that we don't panic
        }
    }
});