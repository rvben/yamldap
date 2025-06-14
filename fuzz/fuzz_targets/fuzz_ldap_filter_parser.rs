#![no_main]

use libfuzzer_sys::fuzz_target;
use yamldap::ldap::parse_ldap_filter;

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string - if it's not valid UTF-8, that's fine
    if let Ok(filter_str) = std::str::from_utf8(data) {
        // Try to parse the filter
        // The parser should handle any malformed input gracefully
        match parse_ldap_filter(filter_str) {
            Ok(_filter) => {
                // Successfully parsed a filter
            }
            Err(_e) => {
                // Parsing error - this is expected for malformed input
                // The important thing is that we don't panic
            }
        }
    }
});