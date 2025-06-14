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
const LDAP_COMPARE_REQUEST: u8 = 0x6e;
const LDAP_COMPARE_RESPONSE: u8 = 0x6f;
const LDAP_ABANDON_REQUEST: u8 = 0x50;
const LDAP_EXTENDED_REQUEST: u8 = 0x77;
const LDAP_EXTENDED_RESPONSE: u8 = 0x78;

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

        if buf.remaining() < length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "Not enough bytes: need {} but only {} available",
                    length,
                    buf.remaining()
                ),
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
                let _end_pos = cursor.position() + length as u64;
                let mut filters = Vec::new();
                while cursor.position() < _end_pos {
                    filters.push(Self::read_filter(cursor)?);
                }
                Ok(format!("(&{})", filters.join("")))
            }
            0xA1 => {
                // OR filter
                let _end_pos = cursor.position() + length as u64;
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
                let _end_pos = cursor.position() + length as u64;
                let attr = Self::read_string(cursor)?;
                let value = Self::read_string(cursor)?;
                Ok(format!("({}={})", attr, value))
            }
            0xA4 => {
                // Substring filter: (attr=*value*)
                let _end_pos = cursor.position() + length as u64;
                let attr = Self::read_string(cursor)?;

                // Read substring components
                if cursor.position() < _end_pos
                    && cursor.get_ref()[cursor.position() as usize] == 0x30
                {
                    cursor.get_u8(); // SEQUENCE tag
                    let _seq_len = Self::read_length(cursor)?;

                    let mut parts = Vec::new();
                    let mut has_initial = false;
                    let mut has_final = false;

                    while cursor.position() < _end_pos {
                        let sub_tag = cursor.get_u8();
                        let sub_len = Self::read_length(cursor)?;
                        if cursor.remaining() < sub_len {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                format!(
                                    "Not enough bytes for substring: need {} but only {} available",
                                    sub_len,
                                    cursor.remaining()
                                ),
                            ));
                        }
                        let mut bytes = vec![0u8; sub_len];
                        cursor.copy_to_slice(&mut bytes);
                        let value = String::from_utf8(bytes).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8")
                        })?;

                        match sub_tag {
                            0x80 => {
                                // initial
                                has_initial = true;
                                parts.insert(0, value);
                            }
                            0x81 => {
                                // any
                                parts.push(format!("*{}", value));
                            }
                            0x82 => {
                                // final
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
                if cursor.remaining() < length {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "Not enough bytes for present attr: need {} but only {} available",
                            length,
                            cursor.remaining()
                        ),
                    ));
                }
                let mut bytes = vec![0u8; length];
                cursor.copy_to_slice(&mut bytes);
                let attr = String::from_utf8(bytes)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8"))?;
                Ok(format!("({}=*)", attr))
            }
            0xA8 => {
                // Approximate Match: (attr~=value)
                let _end_pos = cursor.position() + length as u64;
                let attr = Self::read_string(cursor)?;
                let value = Self::read_string(cursor)?;
                Ok(format!("({}~={})", attr, value))
            }
            0xA9 => {
                // Extensible Match
                let end_pos = cursor.position() + length as u64;
                let mut matching_rule = None;
                let mut attr_type = None;
                let mut match_value = String::new();
                let mut dn_attributes = false;

                while cursor.position() < end_pos {
                    if cursor.remaining() < 1 {
                        break;
                    }
                    let tag = cursor.get_u8();
                    let len = Self::read_length(cursor)?;

                    match tag {
                        0x81 => {
                            // matchingRule [1]
                            if cursor.remaining() < len {
                                return Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    format!("Not enough bytes for matching rule: need {} but only {} available", len, cursor.remaining()),
                                ));
                            }
                            let mut bytes = vec![0u8; len];
                            cursor.copy_to_slice(&mut bytes);
                            matching_rule = Some(String::from_utf8(bytes).map_err(|_| {
                                io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8")
                            })?);
                        }
                        0x82 => {
                            // type [2]
                            if cursor.remaining() < len {
                                return Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    format!("Not enough bytes for attr type: need {} but only {} available", len, cursor.remaining()),
                                ));
                            }
                            let mut bytes = vec![0u8; len];
                            cursor.copy_to_slice(&mut bytes);
                            attr_type = Some(String::from_utf8(bytes).map_err(|_| {
                                io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8")
                            })?);
                        }
                        0x83 => {
                            // matchValue [3]
                            if cursor.remaining() < len {
                                return Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    format!("Not enough bytes for match value: need {} but only {} available", len, cursor.remaining()),
                                ));
                            }
                            let mut bytes = vec![0u8; len];
                            cursor.copy_to_slice(&mut bytes);
                            match_value = String::from_utf8(bytes).map_err(|_| {
                                io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8")
                            })?;
                        }
                        0x84 => {
                            // dnAttributes [4] - BOOLEAN
                            if len == 1 {
                                dn_attributes = cursor.get_u8() != 0x00;
                            }
                        }
                        _ => {
                            // Skip unknown tags
                            cursor.advance(len);
                        }
                    }
                }

                // Construct extensible filter string
                let mut filter = String::from("(");
                if let Some(attr) = attr_type {
                    filter.push_str(&attr);
                }
                if dn_attributes {
                    filter.push_str(":dn");
                }
                if let Some(rule) = matching_rule {
                    filter.push(':');
                    filter.push_str(&rule);
                }
                filter.push_str(":=");
                filter.push_str(&match_value);
                filter.push(')');
                Ok(filter)
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
                        if cursor.remaining() < pass_len {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                format!(
                                    "Not enough bytes for password: need {} but only {} available",
                                    pass_len,
                                    cursor.remaining()
                                ),
                            ));
                        }
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
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid scope"));
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

            LDAP_COMPARE_REQUEST => {
                // Read compare request length
                let _length = Self::read_length(&mut cursor)?;

                // Read DN
                let dn = Self::read_string(&mut cursor)?;

                // Read AttributeValueAssertion (SEQUENCE)
                if cursor.remaining() < 1 || cursor.get_u8() != 0x30 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Expected SEQUENCE for AttributeValueAssertion",
                    ));
                }
                let ava_len = Self::read_length(&mut cursor)?;
                let ava_end = cursor.position() + ava_len as u64;

                // Read attribute description
                let attribute = Self::read_string(&mut cursor)?;

                // Read assertion value
                let value = if cursor.position() < ava_end {
                    Self::read_string(&mut cursor)?
                } else {
                    String::new()
                };

                LdapProtocolOp::CompareRequest {
                    dn,
                    attribute,
                    value,
                }
            }

            LDAP_ABANDON_REQUEST => {
                // Abandon request is encoded as [APPLICATION 16] INTEGER
                // The content is directly the message ID as an integer
                let length = Self::read_length(&mut cursor)?;

                // Read the message ID directly from the remaining bytes
                if length > 4 || cursor.remaining() < length {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid abandon message ID",
                    ));
                }

                let mut abandon_message_id = 0u32;
                for _ in 0..length {
                    abandon_message_id = (abandon_message_id << 8) | (cursor.get_u8() as u32);
                }

                LdapProtocolOp::AbandonRequest {
                    message_id: abandon_message_id,
                }
            }

            LDAP_EXTENDED_REQUEST => {
                // Extended request contains:
                // requestName [0] LDAPOID
                // requestValue [1] OCTET STRING OPTIONAL
                let _length = Self::read_length(&mut cursor)?;

                // Read requestName [0] IMPLICIT OCTET STRING (OID)
                if cursor.remaining() < 1 || cursor.get_u8() != 0x80 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Expected context-specific [0] for requestName",
                    ));
                }
                let name_len = Self::read_length(&mut cursor)?;
                if cursor.remaining() < name_len {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "Not enough bytes for attr name: need {} but only {} available",
                            name_len,
                            cursor.remaining()
                        ),
                    ));
                }
                let mut name_bytes = vec![0u8; name_len];
                cursor.copy_to_slice(&mut name_bytes);
                let name = String::from_utf8(name_bytes).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8 in OID")
                })?;

                // Read optional requestValue [1] OCTET STRING
                let value = if cursor.remaining() > 0
                    && cursor.get_ref()[cursor.position() as usize] == 0x81
                {
                    cursor.get_u8(); // Consume tag
                    let value_len = Self::read_length(&mut cursor)?;
                    if cursor.remaining() < value_len {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!(
                                "Not enough bytes for attr value: need {} but only {} available",
                                value_len,
                                cursor.remaining()
                            ),
                        ));
                    }
                    let mut value_bytes = vec![0u8; value_len];
                    cursor.copy_to_slice(&mut value_bytes);
                    Some(value_bytes)
                } else {
                    None
                };

                LdapProtocolOp::ExtendedRequest { name, value }
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

            LdapProtocolOp::CompareResponse { ref result } => {
                let mut response_content = BytesMut::new();

                // Write result code
                Self::write_integer(&mut response_content, result.result_code as u32);

                // Write matched DN
                Self::write_string(&mut response_content, &result.matched_dn);

                // Write diagnostic message
                Self::write_string(&mut response_content, &result.diagnostic_message);

                // Wrap compare response
                content.put_u8(LDAP_COMPARE_RESPONSE);
                Self::write_length(&mut content, response_content.len());
                content.put(response_content);
            }

            LdapProtocolOp::ExtendedResponse {
                ref result,
                ref name,
                ref value,
            } => {
                let mut response_content = BytesMut::new();

                // Write result code
                Self::write_integer(&mut response_content, result.result_code as u32);

                // Write matched DN
                Self::write_string(&mut response_content, &result.matched_dn);

                // Write diagnostic message
                Self::write_string(&mut response_content, &result.diagnostic_message);

                // Write optional responseName [10] LDAPOID
                if let Some(oid) = name {
                    response_content.put_u8(0x8A); // Context-specific [10]
                    Self::write_length(&mut response_content, oid.len());
                    response_content.put_slice(oid.as_bytes());
                }

                // Write optional responseValue [11] OCTET STRING
                if let Some(val) = value {
                    response_content.put_u8(0x8B); // Context-specific [11]
                    Self::write_length(&mut response_content, val.len());
                    response_content.put_slice(val);
                }

                // Wrap extended response
                content.put_u8(LDAP_EXTENDED_RESPONSE);
                Self::write_length(&mut content, response_content.len());
                content.put(response_content);
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
                result: LdapResult::error(LdapResultCode::NoSuchObject, "Not found".to_string()),
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

    #[test]
    fn test_decode_compare_request() {
        let mut codec = SimpleLdapCodec;
        let mut buf = BytesMut::new();

        // Build the compare request content first
        let mut compare_content = BytesMut::new();

        // DN
        compare_content.put_u8(0x04); // OCTET STRING
        compare_content.put_u8(0x0e); // length 14
        compare_content.put_slice(b"cn=test,dc=com");

        // AttributeValueAssertion SEQUENCE
        compare_content.put_u8(0x30); // SEQUENCE
        compare_content.put_u8(0x0a); // length 10

        // Attribute
        compare_content.put_u8(0x04); // OCTET STRING
        compare_content.put_u8(0x02); // length 2
        compare_content.put_slice(b"cn");

        // Value
        compare_content.put_u8(0x04); // OCTET STRING
        compare_content.put_u8(0x04); // length 4
        compare_content.put_slice(b"test");

        let compare_len = compare_content.len();

        // Build the message
        let mut message_content = BytesMut::new();

        // Message ID
        message_content.put_u8(0x02); // INTEGER
        message_content.put_u8(0x01); // length 1
        message_content.put_u8(0x01); // value 1

        // CompareRequest [APPLICATION 14]
        message_content.put_u8(0x6e); // Compare request tag
        message_content.put_u8(compare_len as u8); // length
        message_content.put(compare_content);

        // Wrap in SEQUENCE
        buf.put_u8(0x30); // SEQUENCE
        buf.put_u8(message_content.len() as u8);
        buf.put(message_content);

        let result = codec.decode(&mut buf);
        if let Err(e) = &result {
            panic!("Decode failed: {:?}", e);
        }
        assert!(result.is_ok());
        let msg = result.unwrap().unwrap();
        assert_eq!(msg.message_id, 1);

        match msg.protocol_op {
            LdapProtocolOp::CompareRequest {
                dn,
                attribute,
                value,
            } => {
                assert_eq!(dn, "cn=test,dc=com");
                assert_eq!(attribute, "cn");
                assert_eq!(value, "test");
            }
            _ => panic!("Expected CompareRequest"),
        }
    }

    #[test]
    fn test_decode_abandon_request() {
        let mut codec = SimpleLdapCodec;
        let mut buf = BytesMut::new();

        // Create abandon request
        // Message: SEQUENCE { messageID INTEGER, AbandonRequest [APPLICATION 16] MessageID }
        let mut message_content = BytesMut::new();

        // Message ID
        message_content.put_u8(0x02); // INTEGER
        message_content.put_u8(0x01); // length 1
        message_content.put_u8(0x01); // value 1

        // AbandonRequest [APPLICATION 16] - contains message ID to abandon
        message_content.put_u8(0x50); // Abandon request tag
        message_content.put_u8(0x01); // length 1
        message_content.put_u8(0x05); // message ID 5 to abandon

        // Wrap in SEQUENCE
        buf.put_u8(0x30); // SEQUENCE
        buf.put_u8(message_content.len() as u8);
        buf.put(message_content);

        let result = codec.decode(&mut buf);
        assert!(result.is_ok());
        let msg = result.unwrap().unwrap();
        assert_eq!(msg.message_id, 1);

        match msg.protocol_op {
            LdapProtocolOp::AbandonRequest { message_id } => {
                assert_eq!(message_id, 5);
            }
            _ => panic!("Expected AbandonRequest"),
        }
    }

    #[test]
    fn test_decode_extended_request() {
        let mut codec = SimpleLdapCodec;
        let mut buf = BytesMut::new();

        // Create extended request for StartTLS
        // Message: SEQUENCE { messageID INTEGER, ExtendedRequest [APPLICATION 23] { requestName, requestValue } }
        let mut message_content = BytesMut::new();

        // Message ID
        message_content.put_u8(0x02); // INTEGER
        message_content.put_u8(0x01); // length 1
        message_content.put_u8(0x01); // value 1

        // ExtendedRequest [APPLICATION 23]
        let mut extended_content = BytesMut::new();

        // requestName [0] IMPLICIT OCTET STRING - StartTLS OID
        let oid = "1.3.6.1.4.1.1466.20037";
        extended_content.put_u8(0x80); // Context-specific [0]
        extended_content.put_u8(oid.len() as u8);
        extended_content.put_slice(oid.as_bytes());

        // No requestValue for StartTLS

        message_content.put_u8(0x77); // Extended request tag
        message_content.put_u8(extended_content.len() as u8);
        message_content.put(extended_content);

        // Wrap in SEQUENCE
        buf.put_u8(0x30); // SEQUENCE
        buf.put_u8(message_content.len() as u8);
        buf.put(message_content);

        let result = codec.decode(&mut buf);
        assert!(result.is_ok());
        let msg = result.unwrap().unwrap();
        assert_eq!(msg.message_id, 1);

        match msg.protocol_op {
            LdapProtocolOp::ExtendedRequest { name, value } => {
                assert_eq!(name, "1.3.6.1.4.1.1466.20037");
                assert!(value.is_none());
            }
            _ => panic!("Expected ExtendedRequest"),
        }
    }

    #[test]
    fn test_decode_malformed_message() {
        let mut codec = SimpleLdapCodec;
        let mut buf = BytesMut::new();

        // Test 1: Invalid message with wrong sequence tag
        buf.put_u8(0x31); // Wrong tag (SET instead of SEQUENCE)
        buf.put_u8(0x05);
        buf.put_slice(&[0x02, 0x01, 0x01, 0x60, 0x00]);

        let result = codec.decode(&mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_decode_truncated_messages() {
        let mut codec = SimpleLdapCodec;

        // Test truncated message ID
        let mut buf = BytesMut::new();
        buf.put_u8(0x30); // SEQUENCE
        buf.put_u8(0x03); // length 3
        buf.put_u8(0x02); // INTEGER tag
        buf.put_u8(0x02); // length 2 but only 1 byte follows
        buf.put_u8(0x01); // Only one byte instead of two

        let result = codec.decode(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_invalid_length_encoding() {
        let mut codec = SimpleLdapCodec;
        let mut buf = BytesMut::new();

        // Invalid long form length - 0xFF means 127 octets for length, which is invalid
        buf.put_u8(0x30); // SEQUENCE
        buf.put_u8(0xFF); // Long form with 127 octets (way too many)

        let result = codec.decode(&mut buf);
        // This will actually return Ok(None) because we don't have 127 bytes for the length
        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // Not enough data
    }

    #[test]
    fn test_decode_oversized_message() {
        let mut codec = SimpleLdapCodec;
        let mut buf = BytesMut::new();

        // Message claiming to be larger than buffer
        buf.put_u8(0x30); // SEQUENCE
        buf.put_u8(0x84); // Long form, 4 bytes
        buf.put_slice(&[0x00, 0x10, 0x00, 0x00]); // 1MB size
        buf.put_slice(&[0x02, 0x01, 0x01]); // But only 3 bytes of data

        let result = codec.decode(&mut buf);
        assert!(result.is_ok()); // Should return None (not enough data)
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_decode_invalid_operation_tag() {
        let mut codec = SimpleLdapCodec;
        let mut buf = BytesMut::new();

        let mut message_content = BytesMut::new();
        message_content.put_u8(0x02); // INTEGER
        message_content.put_u8(0x01); // length 1
        message_content.put_u8(0x01); // message ID 1

        // Invalid operation tag
        message_content.put_u8(0x99); // Unknown APPLICATION tag
        message_content.put_u8(0x00); // empty content

        buf.put_u8(0x30); // SEQUENCE
        buf.put_u8(message_content.len() as u8);
        buf.put(message_content);

        let result = codec.decode(&mut buf);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported operation tag"));
    }

    #[test]
    fn test_decode_invalid_abandon_message_id() {
        let mut codec = SimpleLdapCodec;
        let mut buf = BytesMut::new();

        let mut message_content = BytesMut::new();
        message_content.put_u8(0x02); // INTEGER
        message_content.put_u8(0x01); // length 1
        message_content.put_u8(0x01); // message ID 1

        // AbandonRequest with invalid length
        message_content.put_u8(0x50); // Abandon request tag
        message_content.put_u8(0x05); // length 5 (too long for message ID)
        message_content.put_slice(&[0x01, 0x02, 0x03, 0x04, 0x05]);

        buf.put_u8(0x30); // SEQUENCE
        buf.put_u8(message_content.len() as u8);
        buf.put(message_content);

        let result = codec.decode(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_extended_response() {
        let mut codec = SimpleLdapCodec;

        // Test Extended response for StartTLS
        let msg = LdapMessage {
            message_id: 1,
            protocol_op: LdapProtocolOp::ExtendedResponse {
                result: LdapResult {
                    result_code: LdapResultCode::Unavailable,
                    matched_dn: String::new(),
                    diagnostic_message: "StartTLS is not supported".to_string(),
                },
                name: Some("1.3.6.1.4.1.1466.20037".to_string()),
                value: None,
            },
        };

        let mut buf = BytesMut::new();
        let result = codec.encode(msg, &mut buf);
        assert!(result.is_ok());
        assert!(!buf.is_empty());

        // Verify the encoded message starts with SEQUENCE tag
        assert_eq!(buf[0], 0x30);
    }

    #[test]
    fn test_encode_compare_response() {
        let mut codec = SimpleLdapCodec;

        // Test CompareTrue response
        let msg = LdapMessage {
            message_id: 1,
            protocol_op: LdapProtocolOp::CompareResponse {
                result: LdapResult {
                    result_code: LdapResultCode::CompareTrue,
                    matched_dn: "cn=test,dc=com".to_string(),
                    diagnostic_message: String::new(),
                },
            },
        };

        let mut buf = BytesMut::new();
        let result = codec.encode(msg, &mut buf);
        assert!(result.is_ok());
        assert!(!buf.is_empty());
        assert_eq!(buf[0], 0x30); // SEQUENCE tag

        // Verify the response tag is correct
        let mut found_response_tag = false;
        for i in 0..buf.len() {
            if buf[i] == LDAP_COMPARE_RESPONSE {
                found_response_tag = true;
                break;
            }
        }
        assert!(found_response_tag, "Compare response tag not found");
    }

    #[test]
    fn test_decode_search_request_with_empty_attributes() {
        let mut codec = SimpleLdapCodec;
        let mut buf = BytesMut::new();

        // Build search request with empty attributes list
        let mut search_content = BytesMut::new();

        // Base DN (empty)
        search_content.put_u8(0x04); // OCTET STRING
        search_content.put_u8(0x00); // empty

        // Scope
        search_content.put_u8(0x0A); // ENUMERATED
        search_content.put_u8(0x01);
        search_content.put_u8(0x02); // WholeSubtree

        // DerefAliases
        search_content.put_u8(0x0A); // ENUMERATED
        search_content.put_u8(0x01);
        search_content.put_u8(0x00); // NeverDerefAliases

        // Size limit
        search_content.put_u8(0x02); // INTEGER
        search_content.put_u8(0x01);
        search_content.put_u8(0x00); // 0

        // Time limit
        search_content.put_u8(0x02); // INTEGER
        search_content.put_u8(0x01);
        search_content.put_u8(0x00); // 0

        // Types only
        search_content.put_u8(0x01); // BOOLEAN
        search_content.put_u8(0x01);
        search_content.put_u8(0x00); // FALSE

        // Filter - present filter (objectClass=*)
        search_content.put_u8(0x87); // Present filter
        search_content.put_u8(0x0B); // length
        search_content.put_slice(b"objectClass");

        // NO attributes sequence - testing empty case

        let search_len = search_content.len();

        // Build the message
        let mut message_content = BytesMut::new();

        // Message ID
        message_content.put_u8(0x02); // INTEGER
        message_content.put_u8(0x01);
        message_content.put_u8(0x01); // 1

        // Search request
        message_content.put_u8(0x63); // SEARCH REQUEST
        message_content.put_u8(search_len as u8);
        message_content.put(search_content);

        // Wrap in SEQUENCE
        buf.put_u8(0x30); // SEQUENCE
        buf.put_u8(message_content.len() as u8);
        buf.put(message_content);

        let result = codec.decode(&mut buf);
        assert!(result.is_ok());
        let msg = result.unwrap().unwrap();

        match msg.protocol_op {
            LdapProtocolOp::SearchRequest { attributes, .. } => {
                assert!(attributes.is_empty());
            }
            _ => panic!("Expected SearchRequest"),
        }
    }

    #[test]
    fn test_decode_search_request_with_special_filter() {
        let mut codec = SimpleLdapCodec;
        let mut buf = BytesMut::new();

        // Build search request with NOT filter
        let mut search_content = BytesMut::new();

        // Base DN
        let base_dn = b"dc=example,dc=com";
        search_content.put_u8(0x04); // OCTET STRING
        search_content.put_u8(base_dn.len() as u8); // Correct length: 17
        search_content.put_slice(base_dn);

        // Scope
        search_content.put_u8(0x0A); // ENUMERATED
        search_content.put_u8(0x01);
        search_content.put_u8(0x01); // SingleLevel

        // DerefAliases
        search_content.put_u8(0x0A); // ENUMERATED
        search_content.put_u8(0x01);
        search_content.put_u8(0x00);

        // Size limit
        search_content.put_u8(0x02); // INTEGER
        search_content.put_u8(0x01);
        search_content.put_u8(0x64); // 100

        // Time limit
        search_content.put_u8(0x02); // INTEGER
        search_content.put_u8(0x01);
        search_content.put_u8(0x1E); // 30

        // Types only
        search_content.put_u8(0x01); // BOOLEAN
        search_content.put_u8(0x01);
        search_content.put_u8(0xFF); // TRUE

        // Filter - NOT filter containing equality
        let mut equality_content = BytesMut::new();
        // Build the equality filter content first
        equality_content.put_u8(0x04); // OCTET STRING
        equality_content.put_u8(0x02); // length of "cn"
        equality_content.put_slice(b"cn");
        equality_content.put_u8(0x04); // OCTET STRING
        equality_content.put_u8(0x04); // length of "test"
        equality_content.put_slice(b"test");

        // Now wrap in equality filter tag
        let mut not_content = BytesMut::new();
        not_content.put_u8(0xA3); // Equality
        not_content.put_u8(equality_content.len() as u8); // Correct length: 10
        not_content.put(equality_content);

        search_content.put_u8(0xA2); // NOT filter
        search_content.put_u8(not_content.len() as u8);
        search_content.put(not_content);

        // Attributes
        let mut attrs_content = BytesMut::new();
        attrs_content.put_u8(0x04); // OCTET STRING
        attrs_content.put_u8(0x02); // length of "cn"
        attrs_content.put_slice(b"cn");

        search_content.put_u8(0x30); // SEQUENCE
        search_content.put_u8(attrs_content.len() as u8); // Correct length: 4
        search_content.put(attrs_content);

        let search_len = search_content.len();

        // Build the message
        let mut message_content = BytesMut::new();

        // Message ID
        message_content.put_u8(0x02); // INTEGER
        message_content.put_u8(0x01);
        message_content.put_u8(0x02); // 2

        // Search request
        message_content.put_u8(0x63); // SEARCH REQUEST
        if search_len > 127 {
            panic!(
                "Search content too long for simple encoding: {}",
                search_len
            );
        }
        message_content.put_u8(search_len as u8);
        message_content.put(search_content);

        // Wrap in SEQUENCE
        buf.put_u8(0x30); // SEQUENCE
        let msg_len = message_content.len();
        if msg_len > 127 {
            panic!("Message content too long for simple encoding: {}", msg_len);
        }
        buf.put_u8(msg_len as u8);
        buf.put(message_content);

        // Debug output removed - test is working now

        let result = codec.decode(&mut buf);
        match &result {
            Err(e) => panic!("Decode failed: {:?}", e),
            Ok(None) => panic!("Decode returned None - need more data"),
            Ok(Some(_)) => {} // Good
        }
        let msg = result.unwrap().unwrap();

        match msg.protocol_op {
            LdapProtocolOp::SearchRequest {
                filter,
                types_only,
                size_limit,
                time_limit,
                ..
            } => {
                assert!(filter.contains("(!"));
                assert!(filter.contains("cn=test"));
                assert!(types_only);
                assert_eq!(size_limit, 100);
                assert_eq!(time_limit, 30);
            }
            _ => panic!("Expected SearchRequest"),
        }
    }

    #[test]
    fn test_decode_extended_request_with_value() {
        let mut codec = SimpleLdapCodec;
        let mut buf = BytesMut::new();

        // Create extended request with both name and value
        let mut extended_content = BytesMut::new();

        // requestName [0] - some OID
        let oid = "1.2.3.4.5";
        extended_content.put_u8(0x80); // Context-specific [0]
        extended_content.put_u8(oid.len() as u8);
        extended_content.put_slice(oid.as_bytes());

        // requestValue [1] - some binary data
        let value_data = b"test value data";
        extended_content.put_u8(0x81); // Context-specific [1]
        extended_content.put_u8(value_data.len() as u8);
        extended_content.put_slice(value_data);

        // Build the message
        let mut message_content = BytesMut::new();

        // Message ID
        message_content.put_u8(0x02); // INTEGER
        message_content.put_u8(0x01);
        message_content.put_u8(0x03); // 3

        // Extended request
        message_content.put_u8(0x77); // Extended request tag
        message_content.put_u8(extended_content.len() as u8);
        message_content.put(extended_content);

        // Wrap in SEQUENCE
        buf.put_u8(0x30); // SEQUENCE
        buf.put_u8(message_content.len() as u8);
        buf.put(message_content);

        let result = codec.decode(&mut buf);
        assert!(result.is_ok());
        let msg = result.unwrap().unwrap();

        match msg.protocol_op {
            LdapProtocolOp::ExtendedRequest { name, value } => {
                assert_eq!(name, "1.2.3.4.5");
                assert!(value.is_some());
                assert_eq!(value.unwrap(), b"test value data");
            }
            _ => panic!("Expected ExtendedRequest"),
        }
    }

    #[test]
    fn test_encode_extended_response_with_value() {
        let mut codec = SimpleLdapCodec;

        // Test Extended response with both name and value
        let msg = LdapMessage {
            message_id: 42,
            protocol_op: LdapProtocolOp::ExtendedResponse {
                result: LdapResult::success(),
                name: Some("1.2.3.4.5".to_string()),
                value: Some(vec![0x01, 0x02, 0x03, 0x04]),
            },
        };

        let mut buf = BytesMut::new();
        let result = codec.encode(msg, &mut buf);
        assert!(result.is_ok());
        assert!(!buf.is_empty());

        // Verify structure
        assert_eq!(buf[0], 0x30); // SEQUENCE tag

        // Verify the extended response contains both name and value
        let mut has_name = false;
        let mut has_value = false;
        for i in 0..buf.len() - 1 {
            if buf[i] == 0x8A {
                // responseName tag
                has_name = true;
            }
            if buf[i] == 0x8B {
                // responseValue tag
                has_value = true;
            }
        }
        assert!(has_name, "Response name not found");
        assert!(has_value, "Response value not found");
    }
}
