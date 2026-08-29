//! Distinguished-name parsing and structural operations.
//!
//! The parser accepts the RFC 4514 string representation.  Semantic keys
//! deliberately live beside the parsed representation so storage and scope
//! checks never have to infer DN structure from strings.

use std::fmt;

const MAX_DN_BYTES: usize = 16 * 1024;
const MAX_RDNS: usize = 256;
const MAX_AVAS_PER_RDN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistinguishedName {
    // RFC 4514 string order: most-specific (leaf) RDN first.
    rdns: Vec<RelativeDistinguishedName>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelativeDistinguishedName {
    avas: Vec<AttributeValueAssertion>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeValueAssertion {
    attribute: String,
    value: DnValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DnValue {
    Text(String),
    Ber(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnKey(Vec<RdnKey>);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RdnKey(Vec<AvaKey>);

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct AvaKey {
    attribute: String,
    value: NormalizedDnValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum NormalizedDnValue {
    Text(String),
    Ber(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid distinguished name at byte {offset}: {message}")]
pub struct DnParseError {
    pub offset: usize,
    pub message: String,
}

impl DnParseError {
    fn new(offset: usize, message: impl Into<String>) -> Self {
        Self {
            offset,
            message: message.into(),
        }
    }
}

impl DistinguishedName {
    pub fn parse(input: &str) -> Result<Self, DnParseError> {
        if input.len() > MAX_DN_BYTES {
            return Err(DnParseError::new(
                MAX_DN_BYTES,
                format!("DN exceeds the {MAX_DN_BYTES}-byte limit"),
            ));
        }
        if input.is_empty() {
            return Ok(Self { rdns: Vec::new() });
        }

        let rdn_ranges = split_unescaped(input, b',')?;
        if rdn_ranges.len() > MAX_RDNS {
            return Err(DnParseError::new(
                0,
                format!("DN exceeds the {MAX_RDNS}-RDN limit"),
            ));
        }

        let mut rdns = Vec::with_capacity(rdn_ranges.len());
        for (rdn_start, rdn_end) in rdn_ranges {
            if rdn_start == rdn_end {
                return Err(DnParseError::new(rdn_start, "empty RDN"));
            }
            let rdn_text = &input[rdn_start..rdn_end];
            let ava_ranges = split_unescaped(rdn_text, b'+')?;
            if ava_ranges.len() > MAX_AVAS_PER_RDN {
                return Err(DnParseError::new(
                    rdn_start,
                    format!("RDN exceeds the {MAX_AVAS_PER_RDN}-AVA limit"),
                ));
            }

            let mut avas = Vec::with_capacity(ava_ranges.len());
            let mut seen_attributes = Vec::with_capacity(ava_ranges.len());
            for (ava_start, ava_end) in ava_ranges {
                let absolute_start = rdn_start + ava_start;
                if ava_start == ava_end {
                    return Err(DnParseError::new(absolute_start, "empty AVA"));
                }
                let ava_text = &rdn_text[ava_start..ava_end];
                let equals = find_unescaped(ava_text, b'=')?
                    .ok_or_else(|| DnParseError::new(absolute_start, "AVA is missing '='"))?;
                let attribute = &ava_text[..equals];
                validate_attribute_type(attribute, absolute_start)?;
                let canonical_attribute = canonical_attribute_type(attribute);
                if seen_attributes.contains(&canonical_attribute) {
                    return Err(DnParseError::new(
                        absolute_start,
                        format!("attribute type '{attribute}' occurs more than once in an RDN"),
                    ));
                }
                seen_attributes.push(canonical_attribute);

                let value = parse_value(&ava_text[equals + 1..], absolute_start + equals + 1)?;
                avas.push(AttributeValueAssertion {
                    attribute: attribute.to_string(),
                    value,
                });
            }
            rdns.push(RelativeDistinguishedName { avas });
        }

        Ok(Self { rdns })
    }

    pub fn key(&self) -> DnKey {
        DnKey(
            self.rdns
                .iter()
                .map(RelativeDistinguishedName::key)
                .collect(),
        )
    }

    pub fn is_empty(&self) -> bool {
        self.rdns.is_empty()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.rdns.len()
    }

    pub fn rdns(&self) -> &[RelativeDistinguishedName] {
        &self.rdns
    }

    pub fn leaf_rdn(&self) -> Option<&RelativeDistinguishedName> {
        self.rdns.first()
    }

    pub fn is_descendant_of(&self, parent: &Self) -> bool {
        self.rdns.len() > parent.rdns.len() && self.has_suffix(parent)
    }

    pub fn is_direct_child_of(&self, parent: &Self) -> bool {
        self.rdns.len() == parent.rdns.len() + 1 && self.has_suffix(parent)
    }

    pub fn is_equal_to_or_descendant_of(&self, parent: &Self) -> bool {
        self.rdns.len() >= parent.rdns.len() && self.has_suffix(parent)
    }

    pub fn rebase(&self, old_base: &Self, new_base: &Self) -> Option<Self> {
        if !self.is_equal_to_or_descendant_of(old_base) {
            return None;
        }
        let prefix_len = self.rdns.len() - old_base.rdns.len();
        let mut rdns = self.rdns[..prefix_len].to_vec();
        rdns.extend_from_slice(&new_base.rdns);
        Some(Self { rdns })
    }

    fn has_suffix(&self, suffix: &Self) -> bool {
        let self_key = self.key();
        let suffix_key = suffix.key();
        self_key
            .0
            .get(self_key.0.len().saturating_sub(suffix_key.0.len())..)
            == Some(suffix_key.0.as_slice())
    }
}

impl RelativeDistinguishedName {
    pub fn avas(&self) -> &[AttributeValueAssertion] {
        &self.avas
    }

    fn key(&self) -> RdnKey {
        let mut avas: Vec<AvaKey> = self.avas.iter().map(AttributeValueAssertion::key).collect();
        avas.sort();
        RdnKey(avas)
    }
}

impl AttributeValueAssertion {
    pub fn attribute(&self) -> &str {
        &self.attribute
    }

    pub fn text_value(&self) -> Option<&str> {
        match &self.value {
            DnValue::Text(value) => Some(value),
            DnValue::Ber(_) => None,
        }
    }

    fn key(&self) -> AvaKey {
        let value = match &self.value {
            DnValue::Text(value) => NormalizedDnValue::Text(normalize_text_value(value)),
            DnValue::Ber(value) => NormalizedDnValue::Ber(value.clone()),
        };
        AvaKey {
            attribute: canonical_attribute_type(&self.attribute),
            value,
        }
    }
}

impl fmt::Display for DistinguishedName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (rdn_index, rdn) in self.rdns.iter().enumerate() {
            if rdn_index != 0 {
                formatter.write_str(",")?;
            }
            for (ava_index, ava) in rdn.avas.iter().enumerate() {
                if ava_index != 0 {
                    formatter.write_str("+")?;
                }
                write!(formatter, "{}=", ava.attribute)?;
                match &ava.value {
                    DnValue::Text(value) => formatter.write_str(&escape_text_value(value))?,
                    DnValue::Ber(bytes) => {
                        formatter.write_str("#")?;
                        for byte in bytes {
                            write!(formatter, "{byte:02X}")?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn split_unescaped(input: &str, delimiter: u8) -> Result<Vec<(usize, usize)>, DnParseError> {
    let bytes = input.as_bytes();
    let mut ranges = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => {
                if index + 1 >= bytes.len() {
                    return Err(DnParseError::new(index, "trailing escape"));
                }
                index += if index + 2 < bytes.len()
                    && bytes[index + 1].is_ascii_hexdigit()
                    && bytes[index + 2].is_ascii_hexdigit()
                {
                    3
                } else {
                    2
                };
            }
            byte if byte == delimiter => {
                ranges.push((start, index));
                start = index + 1;
                index += 1;
            }
            _ => index += 1,
        }
    }
    ranges.push((start, bytes.len()));
    Ok(ranges)
}

fn find_unescaped(input: &str, needle: u8) -> Result<Option<usize>, DnParseError> {
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            if index + 1 >= bytes.len() {
                return Err(DnParseError::new(index, "trailing escape"));
            }
            index += if index + 2 < bytes.len()
                && bytes[index + 1].is_ascii_hexdigit()
                && bytes[index + 2].is_ascii_hexdigit()
            {
                3
            } else {
                2
            };
        } else if bytes[index] == needle {
            return Ok(Some(index));
        } else {
            index += 1;
        }
    }
    Ok(None)
}

fn validate_attribute_type(attribute: &str, offset: usize) -> Result<(), DnParseError> {
    if attribute.is_empty() {
        return Err(DnParseError::new(offset, "empty attribute type"));
    }
    let is_descriptor = attribute
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
        && attribute
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-');
    let is_oid = attribute
        .split('.')
        .all(|part| !part.is_empty() && part.as_bytes().iter().all(u8::is_ascii_digit))
        && attribute.contains('.');
    if is_descriptor || is_oid {
        Ok(())
    } else {
        Err(DnParseError::new(offset, "invalid attribute type"))
    }
}

fn parse_value(value: &str, offset: usize) -> Result<DnValue, DnParseError> {
    if let Some(hex) = value.strip_prefix('#') {
        if hex.is_empty() || hex.len() % 2 != 0 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(DnParseError::new(offset, "invalid BER hex value"));
        }
        let bytes = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| decode_hex_pair(pair[0], pair[1]))
            .collect();
        return Ok(DnValue::Ber(bytes));
    }

    let source = value.as_bytes();
    if source.first() == Some(&b' ') || source.first() == Some(&b'#') {
        return Err(DnParseError::new(
            offset,
            "leading space or '#' must be escaped",
        ));
    }
    if source.last() == Some(&b' ') {
        return Err(DnParseError::new(
            offset + source.len() - 1,
            "trailing space must be escaped",
        ));
    }

    let mut decoded = Vec::with_capacity(source.len());
    let mut index = 0;
    while index < source.len() {
        let byte = source[index];
        if byte == b'\\' {
            if index + 1 >= source.len() {
                return Err(DnParseError::new(offset + index, "trailing escape"));
            }
            if index + 2 < source.len()
                && source[index + 1].is_ascii_hexdigit()
                && source[index + 2].is_ascii_hexdigit()
            {
                decoded.push(decode_hex_pair(source[index + 1], source[index + 2]));
                index += 3;
                continue;
            }
            let escaped = source[index + 1];
            if !matches!(
                escaped,
                b' ' | b'"' | b'#' | b'+' | b',' | b';' | b'<' | b'=' | b'>' | b'\\'
            ) {
                return Err(DnParseError::new(offset + index, "invalid escape"));
            }
            decoded.push(escaped);
            index += 2;
            continue;
        }
        if byte == 0 || matches!(byte, b'"' | b'+' | b',' | b';' | b'<' | b'>') {
            return Err(DnParseError::new(
                offset + index,
                "special character must be escaped",
            ));
        }
        decoded.push(byte);
        index += 1;
    }

    String::from_utf8(decoded)
        .map(DnValue::Text)
        .map_err(|_| DnParseError::new(offset, "escaped value is not valid UTF-8"))
}

fn decode_hex_pair(high: u8, low: u8) -> u8 {
    fn digit(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => unreachable!("validated hex digit"),
        }
    }
    digit(high) * 16 + digit(low)
}

fn canonical_attribute_type(attribute: &str) -> String {
    match attribute.to_ascii_lowercase().as_str() {
        "cn" | "2.5.4.3" => "2.5.4.3",
        "l" | "2.5.4.7" => "2.5.4.7",
        "st" | "2.5.4.8" => "2.5.4.8",
        "o" | "2.5.4.10" => "2.5.4.10",
        "ou" | "2.5.4.11" => "2.5.4.11",
        "c" | "2.5.4.6" => "2.5.4.6",
        "street" | "2.5.4.9" => "2.5.4.9",
        "dc" | "0.9.2342.19200300.100.1.25" => "0.9.2342.19200300.100.1.25",
        "uid" | "0.9.2342.19200300.100.1.1" => "0.9.2342.19200300.100.1.1",
        _ => return attribute.to_ascii_lowercase(),
    }
    .to_string()
}

pub(crate) fn attribute_types_equivalent(left: &str, right: &str) -> bool {
    canonical_attribute_type(left) == canonical_attribute_type(right)
}

pub(crate) fn naming_values_equal(left: &str, right: &str) -> bool {
    normalize_text_value(left) == normalize_text_value(right)
}

fn normalize_text_value(value: &str) -> String {
    // The supported naming attributes use case-ignore-style matching.  This
    // captures case folding and insignificant-space handling while keeping
    // the normalization implementation local to DN identity.
    let folded: String = value.chars().flat_map(char::to_lowercase).collect();
    folded.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn escape_text_value(value: &str) -> String {
    let mut output = String::new();
    let chars: Vec<char> = value.chars().collect();
    for (index, character) in chars.iter().copied().enumerate() {
        let leading = index == 0;
        let trailing = index + 1 == chars.len();
        if character == '\0' {
            output.push_str("\\00");
        } else if (character == ' ' && (leading || trailing))
            || (leading && character == '#')
            || matches!(character, '"' | '+' | ',' | ';' | '<' | '>' | '\\')
        {
            output.push('\\');
            output.push(character);
        } else {
            output.push(character);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_escaped_commas_as_one_rdn() {
        let dn = DistinguishedName::parse(r"CN=Smith\, John,OU=People,DC=example,DC=com").unwrap();
        assert_eq!(dn.len(), 4);
        assert_eq!(
            dn.leaf_rdn().unwrap().avas()[0].text_value(),
            Some("Smith, John")
        );
        assert!(dn
            .is_direct_child_of(&DistinguishedName::parse("OU=People,DC=example,DC=com").unwrap()));
    }

    #[test]
    fn multivalued_rdn_order_does_not_affect_identity() {
        let left = DistinguishedName::parse("OU=Sales+CN=J. Smith,DC=example,DC=net").unwrap();
        let right = DistinguishedName::parse("cn=J. Smith+ou=Sales,dc=example,dc=net").unwrap();
        assert_eq!(left.key(), right.key());
    }

    #[test]
    fn descriptor_oid_aliases_have_one_identity() {
        let descriptor = DistinguishedName::parse("CN=Alice,DC=example,DC=com").unwrap();
        let oid = DistinguishedName::parse(
            "2.5.4.3=alice,0.9.2342.19200300.100.1.25=example,0.9.2342.19200300.100.1.25=com",
        )
        .unwrap();
        assert_eq!(descriptor.key(), oid.key());
    }

    #[test]
    fn rebase_replaces_rdn_suffix_not_text() {
        let dn = DistinguishedName::parse(r"CN=dc\=old\,dc\=com,OU=People,DC=old,DC=com").unwrap();
        let old = DistinguishedName::parse("DC=old,DC=com").unwrap();
        let new = DistinguishedName::parse("DC=new,DC=org").unwrap();
        let rebased = dn.rebase(&old, &new).unwrap();
        assert_eq!(
            rebased.to_string(),
            r"CN=dc=old\,dc=com,OU=People,DC=new,DC=org"
        );
    }

    #[test]
    fn rejects_malformed_and_duplicate_avas() {
        for invalid in [
            "CN=Alice\\",
            "CN= Alice",
            "CN=Alice ",
            "CN=#123",
            "CN=Alice+2.5.4.3=Other,DC=example",
            "CN=Alice,,DC=example",
        ] {
            assert!(DistinguishedName::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn render_parse_round_trip_preserves_identity() {
        let parsed = DistinguishedName::parse(
            r#"CN=James \"Jim\" Smith\, III+UID=jsmith,DC=example,DC=net"#,
        )
        .unwrap();
        let rendered = parsed.to_string();
        assert_eq!(
            parsed.key(),
            DistinguishedName::parse(&rendered).unwrap().key()
        );
    }
}
