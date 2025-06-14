# Fuzz Testing for yamldap

This directory contains fuzz tests for yamldap's LDAP protocol decoder and filter parser.

## Prerequisites

Install cargo-fuzz:
```bash
cargo install cargo-fuzz
```

## Running Fuzz Tests

### LDAP Decoder Fuzzing

Tests the LDAP message decoder with random binary input:
```bash
cargo +nightly fuzz run fuzz_ldap_decoder
```

### LDAP Filter Parser Fuzzing

Tests the LDAP filter parser with random string input:
```bash
cargo +nightly fuzz run fuzz_ldap_filter_parser
```

### Structured LDAP Message Fuzzing

Tests the decoder with semi-structured LDAP messages:
```bash
cargo +nightly fuzz run fuzz_ldap_structured
```

## Running with Options

Run for a specific duration:
```bash
cargo +nightly fuzz run fuzz_ldap_decoder -- -max_total_time=60
```

Run with more worker threads:
```bash
cargo +nightly fuzz run fuzz_ldap_decoder -- -workers=4
```

## Analyzing Crashes

If a crash is found, it will be saved in `fuzz/artifacts/<target_name>/`. To reproduce:

```bash
cargo +nightly fuzz run fuzz_ldap_decoder fuzz/artifacts/fuzz_ldap_decoder/crash-<hash>
```

## Coverage

To generate coverage information:
```bash
cargo +nightly fuzz coverage fuzz_ldap_decoder
cargo +nightly fuzz coverage fuzz_ldap_filter_parser
```

## What These Tests Check

1. **fuzz_ldap_decoder**: Ensures the LDAP decoder handles arbitrary binary input without panicking
2. **fuzz_ldap_filter_parser**: Ensures the filter parser handles arbitrary string input gracefully
3. **fuzz_ldap_structured**: Tests with semi-valid LDAP message structures to find edge cases

The goal is to ensure yamldap never panics or hangs when receiving malformed input from clients.