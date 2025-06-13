// Simplified LDAP protocol implementation for testing
// This implements a basic subset of LDAP without full ASN.1 complexity

use bytes::{Buf, BufMut, BytesMut};
use std::io::{self, Cursor};
use tokio_util::codec::{Decoder, Encoder};
use tracing::debug;

use super::protocol::*;

const LDAP_BIND_REQUEST: u8 = 0x60;
const LDAP_BIND_RESPONSE: u8 = 0x61;
const LDAP_UNBIND_REQUEST: u8 = 0x42;
const LDAP_SEARCH_REQUEST: u8 = 0x63;
const LDAP_SEARCH_RESULT_ENTRY: u8 = 0x64;
const LDAP_SEARCH_RESULT_DONE: u8 = 0x65;

pub struct SimpleLdapCodec;

impl SimpleLdapCodec {
    fn read_length(buf: &mut Cursor<&[u8]>) -> io::Result<usize> {
        if buf.remaining() < 1 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Not enough data for length",
            ));
        }

        let first_byte = buf.get_u8();
        if first_byte & 0x80 == 0 {
            // Short form
            Ok(first_byte as usize)
        } else {
            // Long form
            let num_octets = (first_byte & 0x7f) as usize;
            if num_octets > 4 || buf.remaining() < num_octets {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid length encoding",
                ));
            }

            let mut length = 0usize;
            for _ in 0..num_octets {
                length = (length << 8) | (buf.get_u8() as usize);
            }
            Ok(length)
        }
    }

    fn write_length(buf: &mut BytesMut, length: usize) {
        if length < 128 {
            buf.put_u8(length as u8);
        } else if length < 256 {
            buf.put_u8(0x81);
            buf.put_u8(length as u8);
        } else if length < 65536 {
            buf.put_u8(0x82);
            buf.put_u16(length as u16);
        } else {
            // For larger lengths, use 3 bytes
            buf.put_u8(0x83);
            buf.put_u8((length >> 16) as u8);
            buf.put_u8((length >> 8) as u8);
            buf.put_u8(length as u8);
        }
    }

    fn read_string(buf: &mut Cursor<&[u8]>) -> io::Result<String> {
        // Read OCTET STRING tag (0x04)
        if buf.remaining() < 1 || buf.get_u8() != 0x04 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Expected OCTET STRING",
            ));
        }

        let length = Self::read_length(buf)?;
        if buf.remaining() < length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Not enough data for string",
            ));
        }

        let mut bytes = vec![0u8; length];
        buf.copy_to_slice(&mut bytes);

        String::from_utf8(bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8"))
    }

    fn write_string(buf: &mut BytesMut, s: &str) {
        buf.put_u8(0x04); // OCTET STRING tag
        Self::write_length(buf, s.len());
        buf.put_slice(s.as_bytes());
    }

    fn read_integer(buf: &mut Cursor<&[u8]>) -> io::Result<u32> {
        // Read INTEGER tag (0x02)
        if buf.remaining() < 1 || buf.get_u8() != 0x02 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Expected INTEGER",
            ));
        }

        let length = Self::read_length(buf)?;
        if length > 4 || buf.remaining() < length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid integer",
            ));
        }

        let mut value = 0u32;
        for _ in 0..length {
            value = (value << 8) | (buf.get_u8() as u32);
        }
        Ok(value)
    }

    fn write_integer(buf: &mut BytesMut, value: u32) {
        buf.put_u8(0x02); // INTEGER tag
        if value < 128 {
            buf.put_u8(1);
            buf.put_u8(value as u8);
        } else if value < 32768 {
            buf.put_u8(2);
            buf.put_u16(value as u16);
        } else {
            buf.put_u8(4);
            buf.put_u32(value);
        }
    }

    fn read_filter(cursor: &mut Cursor<&[u8]>) -> io::Result<String> {
        if cursor.remaining() < 1 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "No filter data",
            ));
        }

        let tag = cursor.get_u8();
        let length = Self::read_length(cursor)?;
        
        // LDAP Filter tags:
        // 0xA0 - AND
        // 0xA1 - OR
        // 0xA2 - NOT
        // 0xA3 - Equality Match
        // 0xA4 - Substring
        // 0xA5 - Greater or Equal
        // 0xA6 - Less or Equal
        // 0x87 - Present (context-specific primitive 7)
        // 0xA8 - Approximate Match
        // 0xA9 - Extensible Match
        
        match tag {
            0xA0 => {
                // AND filter
                let __end_pos = cursor.position() + length as u64;
                let mut filters = Vec::new();
                while cursor.position() < _end_pos {
                    filters.push(Self::read_filter(cursor)?);
                }
                Ok(format!("(&{})", filters.join("")))
            }
            0xA1 => {
                // OR filter
                let __end_pos = cursor.position() + length as u64;
                let mut filters = Vec::new();
                while cursor.position() < _end_pos {
                    filters.push(Self::read_filter(cursor)?);
                }
                Ok(format!("(|{})", filters.join("")))
            }
            0xA2 => {
                // NOT filter
                let filter = Self::read_filter(cursor)?;
                Ok(format!("(!{})", filter))
            }
            0xA3 => {
                // Equality Match: (attr=value)
                let __end_pos = cursor.position() + length as u64;
                let attr = Self::read_string(cursor)?;
                let value = Self::read_string(cursor)?;
                Ok(format!("({}={})", attr, value))
            }
            0xA4 => {
                // Substring filter: (attr=*value*)
                let __end_pos = cursor.position() + length as u64;
                let attr = Self::read_string(cursor)?;
                
                // Read substring components
                if cursor.position() < _end_pos && cursor.get_ref()[cursor.position() as usize] == 0x30 {
                    cursor.get_u8(); // SEQUENCE tag
                    let _seq_len = Self::read_length(cursor)?;
                    
                    let mut parts = Vec::new();
                    let mut has_initial = false;
                    let mut has_final = false;
                    
                    while cursor.position() < _end_pos {
                        let sub_tag = cursor.get_u8();
                        let sub_len = Self::read_length(cursor)?;
                        let mut bytes = vec![0u8; sub_len];
                        cursor.copy_to_slice(&mut bytes);
                        let value = String::from_utf8(bytes).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8")
                        })?;
                        
                        match sub_tag {
                            0x80 => { // initial
                                has_initial = true;
                                parts.insert(0, value);
                            }
                            0x81 => { // any
                                parts.push(format!("*{}", value));
                            }
                            0x82 => { // final
                                has_final = true;
                                parts.push(format!("*{}", value));
                            }
                            _ => {}
                        }
                    }
                    
                    let mut filter = format!("({}=", attr);
                    if !has_initial {
                        filter.push('*');
                    }
                    filter.push_str(&parts.join(""));
                    if !has_final {
                        filter.push('*');
                    }
                    filter.push(')');
                    Ok(filter)
                } else {
                    Ok(format!("({}=*)", attr))
                }
            }
            0xA5 => {
                // Greater or Equal: (attr>=value)
                let attr = Self::read_string(cursor)?;
                let value = Self::read_string(cursor)?;
                Ok(format!("({}>={})", attr, value))
            }
            0xA6 => {
                // Less or Equal: (attr<=value)
                let attr = Self::read_string(cursor)?;
                let value = Self::read_string(cursor)?;
                Ok(format!("({}<={})", attr, value))
            }
            0x87 => {
                // Present: (attr=*)
                let mut bytes = vec![0u8; length];
                cursor.copy_to_slice(&mut bytes);
                let attr = String::from_utf8(bytes).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8")
                })?;
                Ok(format!("({}=*)", attr))
            }
            _ => {
                // Unknown filter type, skip it
                cursor.set_position(cursor.position() + length as u64);
                Ok("(objectClass=*)".to_string()) // Default fallback
            }
        }
    }
}

impl Decoder for SimpleLdapCodec {
    type Item = LdapMessage;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Fast path: check minimum size
        if src.len() < 5 {
            return Ok(None);
        }

        // Peek at the message to determine size without copying
        if src[0] != 0x30 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Expected SEQUENCE",
            ));
        }

        // Quick length check
        let (msg_length, header_len) = if src[1] & 0x80 == 0 {
            // Short form
            (src[1] as usize, 2)
        } else {
            let num_octets = (src[1] & 0x7f) as usize;
            if src.len() < 2 + num_octets {
                return Ok(None);
            }

            let mut length = 0usize;
            for i in 0..num_octets {
                length = (length << 8) | (src[2 + i] as usize);
            }
            (length, 2 + num_octets)
        };

        let total_len = header_len + msg_length;
        if src.len() < total_len {
            return Ok(None); // Need more data
        }

        // Now parse the message
        let mut cursor = Cursor::new(&src[..total_len]);
        cursor.set_position(header_len as u64); // Skip the header we already parsed

        // Read message ID
        let message_id = Self::read_integer(&mut cursor)?;

        // Read operation tag
        let op_tag = cursor.get_u8();

        debug!(
            "Received LDAP message: id={}, op_tag=0x{:02x}",
            message_id, op_tag
        );

        let protocol_op = match op_tag {
            LDAP_BIND_REQUEST => {
                // Read bind request length
                let _length = Self::read_length(&mut cursor)?;

                // Read version
                let version = Self::read_integer(&mut cursor)? as u8;

                // Read DN
                let dn = Self::read_string(&mut cursor)?;

                // Read authentication choice
                let auth = if cursor.remaining() > 0 {
                    let auth_tag = cursor.get_u8();
                    if auth_tag == 0x80 {
                        // Simple authentication
                        let pass_len = Self::read_length(&mut cursor)?;
                        let mut pass_bytes = vec![0u8; pass_len];
                        cursor.copy_to_slice(&mut pass_bytes);
                        let password = String::from_utf8(pass_bytes).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8")
                        })?;
                        BindAuthentication::Simple(password)
                    } else {
                        BindAuthentication::Anonymous
                    }
                } else {
                    BindAuthentication::Anonymous
                };

                LdapProtocolOp::BindRequest {
                    version,
                    dn,
                    authentication: auth,
                }
            }

            LDAP_UNBIND_REQUEST => LdapProtocolOp::UnbindRequest,

            LDAP_SEARCH_REQUEST => {
                // Read search request length
                let _length = Self::read_length(&mut cursor)?;
                
                // Read base DN
                let base_dn = Self::read_string(&mut cursor)?;
                
                // Read scope (ENUMERATED)
                if cursor.remaining() < 1 || cursor.get_u8() != 0x0A {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Expected ENUMERATED for scope",
                    ));
                }
                let scope_len = Self::read_length(&mut cursor)?;
                if scope_len != 1 || cursor.remaining() < 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid scope",
                    ));
                }
                let scope_value = cursor.get_u8();
                let scope = match scope_value {
                    0 => SearchScope::BaseObject,
                    1 => SearchScope::SingleLevel,
                    2 => SearchScope::WholeSubtree,
                    _ => SearchScope::WholeSubtree, // Default to subtree
                };
                
                // Read derefAliases (ENUMERATED)
                if cursor.remaining() < 1 || cursor.get_u8() != 0x0A {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Expected ENUMERATED for derefAliases",
                    ));
                }
                let deref_len = Self::read_length(&mut cursor)?;
                if deref_len != 1 || cursor.remaining() < 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid derefAliases",
                    ));
                }
                let _deref_value = cursor.get_u8(); // We'll use NeverDerefAliases for now
                
                // Read sizeLimit (INTEGER)
                let size_limit = Self::read_integer(&mut cursor)?;
                
                // Read timeLimit (INTEGER)
                let time_limit = Self::read_integer(&mut cursor)?;
                
                // Read typesOnly (BOOLEAN)
                if cursor.remaining() < 1 || cursor.get_u8() != 0x01 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Expected BOOLEAN for typesOnly",
                    ));
                }
                let bool_len = Self::read_length(&mut cursor)?;
                if bool_len != 1 || cursor.remaining() < 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid boolean",
                    ));
                }
                let types_only = cursor.get_u8() != 0x00;
                
                // Read filter - this is complex, so we'll read it as a blob for now
                // and convert to string representation
                let filter = Self::read_filter(&mut cursor)?;
                
                // Read attributes (SEQUENCE OF OCTET STRING)
                let mut attributes = Vec::new();
                if cursor.remaining() > 0 && cursor.get_ref()[cursor.position() as usize] == 0x30 {
                    cursor.get_u8(); // SEQUENCE tag
                    let attrs_len = Self::read_length(&mut cursor)?;
                    let attrs_end = cursor.position() + attrs_len as u64;
                    
                    while cursor.position() < attrs_end {
                        let attr = Self::read_string(&mut cursor)?;
                        attributes.push(attr);
                    }
                }
                
                LdapProtocolOp::SearchRequest {
                    base_dn,
                    scope,
                    deref_aliases: DerefAliases::NeverDerefAliases,
                    size_limit,
                    time_limit,
                    types_only,
                    filter,
                    attributes,
                }
            }

            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unsupported operation tag: 0x{:02x}", op_tag),
                ));
            }
        };

        src.advance(total_len);

        Ok(Some(LdapMessage {
            message_id,
            protocol_op,
        }))
    }
}

impl Encoder<LdapMessage> for SimpleLdapCodec {
    type Error = io::Error;

    fn encode(&mut self, item: LdapMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // Reserve space for the message
        dst.reserve(256);

        // We'll write the message content first, then wrap it
        let mut content = BytesMut::new();

        // Write message ID
        Self::write_integer(&mut content, item.message_id);

        // Write protocol operation
        match item.protocol_op {
            LdapProtocolOp::BindResponse { ref result } => {
                // Start bind response
                let mut bind_content = BytesMut::new();

                // Write result code
                Self::write_integer(&mut bind_content, result.result_code as u32);

                // Write matched DN
                Self::write_string(&mut bind_content, &result.matched_dn);

                // Write diagnostic message
                Self::write_string(&mut bind_content, &result.diagnostic_message);

                // Wrap bind response
                content.put_u8(LDAP_BIND_RESPONSE);
                Self::write_length(&mut content, bind_content.len());
                content.put(bind_content);
            }

            LdapProtocolOp::SearchResultEntry {
                ref dn,
                ref attributes,
            } => {
                let mut entry_content = BytesMut::new();

                // Write DN
                Self::write_string(&mut entry_content, dn);

                // Write attributes sequence
                let mut attrs_content = BytesMut::new();

                for (name, values) in attributes {
                    let mut attr_content = BytesMut::new();

                    // Write attribute name
                    Self::write_string(&mut attr_content, name);

                    // Write values SET
                    let mut values_content = BytesMut::new();
                    for value in values {
                        Self::write_string(&mut values_content, value);
                    }

                    attr_content.put_u8(0x31); // SET tag
                    Self::write_length(&mut attr_content, values_content.len());
                    attr_content.put(values_content);

                    // Wrap attribute in SEQUENCE
                    attrs_content.put_u8(0x30); // SEQUENCE tag
                    Self::write_length(&mut attrs_content, attr_content.len());
                    attrs_content.put(attr_content);
                }

                // Write attributes SEQUENCE
                entry_content.put_u8(0x30); // SEQUENCE tag
                Self::write_length(&mut entry_content, attrs_content.len());
                entry_content.put(attrs_content);

                // Wrap search result entry
                content.put_u8(LDAP_SEARCH_RESULT_ENTRY);
                Self::write_length(&mut content, entry_content.len());
                content.put(entry_content);
            }

            LdapProtocolOp::SearchResultDone { ref result } => {
                let mut done_content = BytesMut::new();

                // Write result code
                Self::write_integer(&mut done_content, result.result_code as u32);

                // Write matched DN
                Self::write_string(&mut done_content, &result.matched_dn);

                // Write diagnostic message
                Self::write_string(&mut done_content, &result.diagnostic_message);

                // Wrap search result done
                content.put_u8(LDAP_SEARCH_RESULT_DONE);
                Self::write_length(&mut content, done_content.len());
                content.put(done_content);
            }

            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unsupported operation for encoding",
                ));
            }
        }

        // Wrap the entire message in a SEQUENCE
        dst.put_u8(0x30); // SEQUENCE tag
        Self::write_length(dst, content.len());
        dst.put(content);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_read_write_length_short_form() {
        // Test short form (< 128)
        let mut buf = BytesMut::new();
        SimpleLdapCodec::write_length(&mut buf, 42);
        
        let mut cursor = Cursor::new(buf.as_ref());
        let length = SimpleLdapCodec::read_length(&mut cursor).unwrap();
        assert_eq!(length, 42);
    }

    #[test]
    fn test_read_write_length_long_form_1_byte() {
        // Test long form with 1 byte (128-255)
        let mut buf = BytesMut::new();
        SimpleLdapCodec::write_length(&mut buf, 200);
        
        let mut cursor = Cursor::new(buf.as_ref());
        let length = SimpleLdapCodec::read_length(&mut cursor).unwrap();
        assert_eq!(length, 200);
    }

    #[test]
    fn test_read_write_length_long_form_2_bytes() {
        // Test long form with 2 bytes (256-65535)
        let mut buf = BytesMut::new();
        SimpleLdapCodec::write_length(&mut buf, 1000);
        
        let mut cursor = Cursor::new(buf.as_ref());
        let length = SimpleLdapCodec::read_length(&mut cursor).unwrap();
        assert_eq!(length, 1000);
    }

    #[test]
    fn test_read_write_length_long_form_3_bytes() {
        // Test long form with 3 bytes (>= 65536)
        let mut buf = BytesMut::new();
        SimpleLdapCodec::write_length(&mut buf, 100000);
        
        let mut cursor = Cursor::new(buf.as_ref());
        let length = SimpleLdapCodec::read_length(&mut cursor).unwrap();
        assert_eq!(length, 100000);
    }

    #[test]
    fn test_read_length_insufficient_data() {
        let buf = vec![];
        let mut cursor = Cursor::new(buf.as_ref());
        let result = SimpleLdapCodec::read_length(&mut cursor);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_read_length_invalid_long_form() {
        // Long form with too many octets
        let buf = vec![0x85]; // Claims 5 octets but we don't have them
        let mut cursor = Cursor::new(buf.as_ref());
        let result = SimpleLdapCodec::read_length(&mut cursor);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_read_write_string() {
        let mut buf = BytesMut::new();
        SimpleLdapCodec::write_string(&mut buf, "hello world");
        
        let mut cursor = Cursor::new(buf.as_ref());
        let string = SimpleLdapCodec::read_string(&mut cursor).unwrap();
        assert_eq!(string, "hello world");
    }

    #[test]
    fn test_read_string_invalid_tag() {
        let buf = vec![0x05]; // Wrong tag
        let mut cursor = Cursor::new(buf.as_ref());
        let result = SimpleLdapCodec::read_string(&mut cursor);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_read_string_insufficient_data() {
        let buf = vec![0x04, 0x10]; // Claims 16 bytes but we don't have them
        let mut cursor = Cursor::new(buf.as_ref());
        let result = SimpleLdapCodec::read_string(&mut cursor);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_read_string_invalid_utf8() {
        let buf = vec![0x04, 0x02, 0xFF, 0xFF]; // Invalid UTF-8
        let mut cursor = Cursor::new(buf.as_ref());
        let result = SimpleLdapCodec::read_string(&mut cursor);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_read_write_integer() {
        let mut buf = BytesMut::new();
        SimpleLdapCodec::write_integer(&mut buf, 42);
        
        let mut cursor = Cursor::new(buf.as_ref());
        let value = SimpleLdapCodec::read_integer(&mut cursor).unwrap();
        assert_eq!(value, 42);
    }

    #[test]
    fn test_read_integer_invalid_tag() {
        let buf = vec![0x03]; // Wrong tag
        let mut cursor = Cursor::new(buf.as_ref());
        let result = SimpleLdapCodec::read_integer(&mut cursor);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_decode_empty_buffer() {
        let mut codec = SimpleLdapCodec;
        let mut buf = BytesMut::new();
        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_decode_partial_message() {
        let mut codec = SimpleLdapCodec;
        let mut buf = BytesMut::from(&[0x30, 0x10][..]); // SEQUENCE with length 16 but no content
        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_decode_invalid_sequence_tag() {
        let mut codec = SimpleLdapCodec;
        let mut buf = BytesMut::from(&[0x31, 0x02, 0x00, 0x00, 0x00][..]); // Wrong tag with 5 bytes
        let result = codec.decode(&mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_encode_bind_request() {
        let mut codec = SimpleLdapCodec;
        let mut buf = BytesMut::new();
        
        let msg = LdapMessage {
            message_id: 1,
            protocol_op: LdapProtocolOp::BindRequest {
                version: 3,
                dn: "".to_string(), // Anonymous bind
                authentication: BindAuthentication::Anonymous,
            },
        };
        
        // BindRequest encoding is not implemented in SimpleLdapCodec
        let result = codec.encode(msg, &mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_encode_bind_response() {
        let mut codec = SimpleLdapCodec;
        let mut buf = BytesMut::new();
        
        let msg = LdapMessage {
            message_id: 1,
            protocol_op: LdapProtocolOp::BindResponse {
                result: LdapResult::success(),
            },
        };
        
        let result = codec.encode(msg, &mut buf);
        assert!(result.is_ok());
        assert!(!buf.is_empty());
    }

    #[test]
    fn test_encode_search_result_entry() {
        let mut codec = SimpleLdapCodec;
        let mut buf = BytesMut::new();
        
        let mut attrs = HashMap::new();
        attrs.insert("cn".to_string(), vec!["test".to_string()]);
        
        let msg = LdapMessage {
            message_id: 2,
            protocol_op: LdapProtocolOp::SearchResultEntry {
                dn: "cn=test,dc=example,dc=com".to_string(),
                attributes: attrs,
            },
        };
        
        let result = codec.encode(msg, &mut buf);
        assert!(result.is_ok());
        assert!(!buf.is_empty());
    }

    #[test]
    fn test_encode_search_result_done() {
        let mut codec = SimpleLdapCodec;
        let mut buf = BytesMut::new();
        
        let msg = LdapMessage {
            message_id: 3,
            protocol_op: LdapProtocolOp::SearchResultDone {
                result: LdapResult::error(
                    LdapResultCode::NoSuchObject,
                    "Not found".to_string(),
                ),
            },
        };
        
        let result = codec.encode(msg, &mut buf);
        assert!(result.is_ok());
        assert!(!buf.is_empty());
    }

    #[test]
    fn test_encode_unsupported_operation() {
        let mut codec = SimpleLdapCodec;
        let mut buf = BytesMut::new();
        
        let msg = LdapMessage {
            message_id: 1,
            protocol_op: LdapProtocolOp::UnbindRequest,
        };
        
        let result = codec.encode(msg, &mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_roundtrip_bind_response() {
        let mut codec = SimpleLdapCodec;
        
        // Encode
        let original = LdapMessage {
            message_id: 42,
            protocol_op: LdapProtocolOp::BindResponse {
                result: LdapResult::success(),
            },
        };
        
        let mut buf = BytesMut::new();
        codec.encode(original.clone(), &mut buf).unwrap();
        
        // This test would require implementing decode for BindResponse
        // For now, just check that encoding succeeded
        assert!(!buf.is_empty());
        assert_eq!(buf[0], 0x30); // SEQUENCE tag
    }

    #[test]
    fn test_write_integer_various_sizes() {
        // Test single byte integer
        let mut buf = BytesMut::new();
        SimpleLdapCodec::write_integer(&mut buf, 127);
        assert_eq!(buf[0], 0x02); // INTEGER tag
        assert_eq!(buf[1], 0x01); // length
        assert_eq!(buf[2], 127);
        
        // Test multi-byte integer
        let mut buf = BytesMut::new();
        SimpleLdapCodec::write_integer(&mut buf, 300);
        assert_eq!(buf[0], 0x02); // INTEGER tag
        assert_eq!(buf[1], 0x02); // length
        assert_eq!(buf[2], 0x01); // high byte
        assert_eq!(buf[3], 0x2C); // low byte (300 = 0x012C)
    }

    #[test]
    fn test_read_integer_multi_byte() {
        // Test reading multi-byte integer
        let buf = vec![0x02, 0x02, 0x01, 0x2C]; // INTEGER 300
        let mut cursor = Cursor::new(buf.as_ref());
        let value = SimpleLdapCodec::read_integer(&mut cursor).unwrap();
        assert_eq!(value, 300);
    }

    #[test]
    fn test_decode_with_debug_logging() {
        let mut codec = SimpleLdapCodec;
        let mut buf = BytesMut::new();
        
        // Create a simple bind request
        buf.put_u8(0x30); // SEQUENCE
        buf.put_u8(0x0C); // length 12
        buf.put_u8(0x02); // INTEGER (message ID)
        buf.put_u8(0x01); // length 1
        buf.put_u8(0x01); // value 1
        buf.put_u8(0x60); // Bind Request
        buf.put_u8(0x07); // length 7
        buf.put_u8(0x02); // INTEGER (version)
        buf.put_u8(0x01); // length 1
        buf.put_u8(0x03); // value 3
        buf.put_u8(0x04); // OCTET STRING (DN)
        buf.put_u8(0x00); // length 0 (empty)
        buf.put_u8(0x80); // Simple auth
        buf.put_u8(0x00); // length 0 (anonymous)
        
        let result = codec.decode(&mut buf);
        assert!(result.is_ok());
        let msg = result.unwrap().unwrap();
        assert_eq!(msg.message_id, 1);
    }
}
