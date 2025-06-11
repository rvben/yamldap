#!/usr/bin/env python3
"""
Simple test script for yamldap server
Requires: pip install python-ldap
"""

import ldap
import sys
import time

def test_ldap_server(host='localhost', port=389):
    """Test basic LDAP operations against yamldap server"""
    
    # Connection string
    ldap_url = f"ldap://{host}:{port}"
    print(f"Connecting to {ldap_url}...")
    
    try:
        # Initialize connection
        conn = ldap.initialize(ldap_url)
        conn.protocol_version = ldap.VERSION3
        
        # Test 1: Anonymous bind
        print("\n1. Testing anonymous bind...")
        try:
            conn.simple_bind_s("", "")
            print("   ✓ Anonymous bind successful")
        except ldap.LDAPError as e:
            print(f"   ✗ Anonymous bind failed: {e}")
        
        # Test 2: User authentication
        print("\n2. Testing user authentication...")
        try:
            conn.simple_bind_s("uid=jdoe,ou=users,dc=example,dc=com", "password123")
            print("   ✓ User bind successful")
        except ldap.INVALID_CREDENTIALS:
            print("   ✗ Invalid credentials")
        except ldap.LDAPError as e:
            print(f"   ✗ Bind failed: {e}")
        
        # Test 3: Search for all entries
        print("\n3. Testing search for all entries...")
        try:
            results = conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, "(objectClass=*)")
            print(f"   ✓ Found {len(results)} entries")
            for dn, attrs in results[:3]:  # Show first 3 entries
                print(f"     - {dn}")
        except ldap.LDAPError as e:
            print(f"   ✗ Search failed: {e}")
        
        # Test 4: Search for specific user
        print("\n4. Testing search for specific user...")
        try:
            results = conn.search_s("ou=users,dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=jdoe)")
            if results:
                dn, attrs = results[0]
                print(f"   ✓ Found user: {dn}")
                for attr, values in attrs.items():
                    print(f"     - {attr}: {values}")
            else:
                print("   ✗ User not found")
        except ldap.LDAPError as e:
            print(f"   ✗ Search failed: {e}")
        
        # Test 5: Search for groups
        print("\n5. Testing search for groups...")
        try:
            results = conn.search_s("ou=groups,dc=example,dc=com", ldap.SCOPE_SUBTREE, "(objectClass=groupOfNames)")
            print(f"   ✓ Found {len(results)} groups")
            for dn, attrs in results:
                print(f"     - {dn}")
                if 'member' in attrs:
                    print(f"       Members: {attrs['member']}")
        except ldap.LDAPError as e:
            print(f"   ✗ Search failed: {e}")
        
        # Clean up
        conn.unbind_s()
        print("\n✓ All tests completed")
        
    except ldap.SERVER_DOWN:
        print(f"✗ Cannot connect to LDAP server at {ldap_url}")
        print("  Make sure yamldap is running with: yamldap -f examples/sample_directory.yaml")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return False
    
    return True

if __name__ == "__main__":
    # Allow custom host/port from command line
    host = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 389
    
    print("YAMLDAP Test Script")
    print("===================")
    
    # Give server time to start if just launched
    time.sleep(1)
    
    success = test_ldap_server(host, port)
    sys.exit(0 if success else 1)