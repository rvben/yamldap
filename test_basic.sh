#!/bin/bash
# Basic LDAP test using ldapsearch command

echo "Basic YAMLDAP Test"
echo "=================="

# Test anonymous bind and search
echo -e "\n1. Testing anonymous search..."
ldapsearch -x -H ldap://localhost:389 -b "dc=example,dc=com" "(objectClass=*)" dn 2>&1 | head -20

# Test authenticated bind
echo -e "\n2. Testing authenticated search..."
ldapsearch -x -H ldap://localhost:389 -D "uid=jdoe,ou=users,dc=example,dc=com" -w password123 -b "dc=example,dc=com" "(uid=jdoe)" 2>&1 | head -20

echo -e "\nNote: If you see connection errors, make sure yamldap is running with:"
echo "  cargo run -- -f examples/sample_directory.yaml"