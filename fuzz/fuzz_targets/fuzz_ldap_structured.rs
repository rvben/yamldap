#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use bytes::{BufMut, BytesMut};
use libfuzzer_sys::fuzz_target;
use tokio_util::codec::Decoder;
use yamldap::ldap::SimpleLdapCodec;

// Define structures for generating semi-valid LDAP messages
#[derive(Arbitrary, Debug)]
struct FuzzLdapMessage {
    sequence_tag: u8,
    length: FuzzLength,
    message_id: FuzzInteger,
    operation: FuzzOperation,
}

#[derive(Arbitrary, Debug)]
enum FuzzLength {
    Short(u8),
    Long { num_octets: u8, value: u32 },
}

#[derive(Arbitrary, Debug)]
struct FuzzInteger {
    tag: u8,
    length: u8,
    value: u32,
}

#[derive(Arbitrary, Debug)]
enum FuzzOperation {
    BindRequest {
        tag: u8,
        length: u8,
        version: u8,
        dn_length: u8,
        dn: Vec<u8>,
        auth_choice: u8,
        password_length: u8,
        password: Vec<u8>,
    },
    SearchRequest {
        tag: u8,
        length: u8,
        base_dn: Vec<u8>,
        scope: u8,
        deref: u8,
        size_limit: u8,
        time_limit: u8,
        types_only: u8,
        filter: Vec<u8>,
    },
    CompareRequest {
        tag: u8,
        length: u8,
        dn: Vec<u8>,
        attribute: Vec<u8>,
        value: Vec<u8>,
    },
    Random {
        tag: u8,
        data: Vec<u8>,
    },
}

impl FuzzLdapMessage {
    fn to_bytes(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        
        // SEQUENCE tag
        buf.put_u8(self.sequence_tag);
        
        // Length encoding
        match &self.length {
            FuzzLength::Short(len) => buf.put_u8(*len),
            FuzzLength::Long { num_octets, value } => {
                buf.put_u8(0x80 | (num_octets & 0x7f));
                for i in (0..*num_octets).rev() {
                    buf.put_u8((value >> (i * 8)) as u8);
                }
            }
        }
        
        // Message ID
        buf.put_u8(self.message_id.tag);
        buf.put_u8(self.message_id.length);
        buf.put_u32(self.message_id.value);
        
        // Operation
        match &self.operation {
            FuzzOperation::BindRequest {
                tag,
                length,
                version,
                dn_length,
                dn,
                auth_choice,
                password_length,
                password,
            } => {
                buf.put_u8(*tag);
                buf.put_u8(*length);
                buf.put_u8(0x02); // INTEGER tag
                buf.put_u8(0x01);
                buf.put_u8(*version);
                buf.put_u8(0x04); // OCTET STRING tag
                buf.put_u8(*dn_length);
                buf.put_slice(&dn[..dn.len().min(*dn_length as usize)]);
                buf.put_u8(*auth_choice);
                buf.put_u8(*password_length);
                buf.put_slice(&password[..password.len().min(*password_length as usize)]);
            }
            FuzzOperation::SearchRequest {
                tag,
                length,
                base_dn,
                scope,
                deref,
                size_limit,
                time_limit,
                types_only,
                filter,
            } => {
                buf.put_u8(*tag);
                buf.put_u8(*length);
                buf.put_u8(0x04); // OCTET STRING for base DN
                buf.put_u8(base_dn.len().min(255) as u8);
                buf.put_slice(&base_dn[..base_dn.len().min(255)]);
                buf.put_u8(0x0A); // ENUMERATED for scope
                buf.put_u8(0x01);
                buf.put_u8(*scope);
                buf.put_u8(0x0A); // ENUMERATED for deref
                buf.put_u8(0x01);
                buf.put_u8(*deref);
                buf.put_u8(0x02); // INTEGER for size limit
                buf.put_u8(0x01);
                buf.put_u8(*size_limit);
                buf.put_u8(0x02); // INTEGER for time limit
                buf.put_u8(0x01);
                buf.put_u8(*time_limit);
                buf.put_u8(0x01); // BOOLEAN for types only
                buf.put_u8(0x01);
                buf.put_u8(*types_only);
                // Filter (simplified - just put raw bytes)
                buf.put_slice(&filter[..filter.len().min(100)]);
            }
            FuzzOperation::CompareRequest {
                tag,
                length,
                dn,
                attribute,
                value,
            } => {
                buf.put_u8(*tag);
                buf.put_u8(*length);
                buf.put_u8(0x04); // OCTET STRING for DN
                buf.put_u8(dn.len().min(255) as u8);
                buf.put_slice(&dn[..dn.len().min(255)]);
                buf.put_u8(0x30); // SEQUENCE for attribute-value
                buf.put_u8((attribute.len() + value.len() + 4).min(255) as u8);
                buf.put_u8(0x04); // OCTET STRING for attribute
                buf.put_u8(attribute.len().min(255) as u8);
                buf.put_slice(&attribute[..attribute.len().min(255)]);
                buf.put_u8(0x04); // OCTET STRING for value
                buf.put_u8(value.len().min(255) as u8);
                buf.put_slice(&value[..value.len().min(255)]);
            }
            FuzzOperation::Random { tag, data } => {
                buf.put_u8(*tag);
                buf.put_slice(&data[..data.len().min(1000)]);
            }
        }
        
        buf
    }
}

fuzz_target!(|data: &[u8]| {
    // Generate structured input from fuzz data
    let mut u = Unstructured::new(data);
    if let Ok(msg) = FuzzLdapMessage::arbitrary(&mut u) {
        let mut buf = msg.to_bytes();
        
        // Try to decode the generated message
        let mut codec = SimpleLdapCodec;
        match codec.decode(&mut buf) {
            Ok(Some(_msg)) => {
                // Successfully decoded
            }
            Ok(None) => {
                // Not enough data
            }
            Err(_e) => {
                // Decoding error - expected for malformed input
            }
        }
    }
});