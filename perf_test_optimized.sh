#!/bin/bash
# Optimized performance test using persistent connections

echo "YAMLDAP Optimized Performance Test"
echo "================================="
echo ""

# Test with persistent connection using ldapsearch -E pr (paged results)
echo "1. Bulk Search Test (1000 queries, single connection)"
start_time=$(date +%s%N)

# Use ldapsearch with multiple filters in one connection
(echo ""; for i in {1..1000}; do echo "(uid=jdoe)"; done) | \
    ldapsearch -x -H ldap://localhost:389 -b "dc=example,dc=com" -f - dn 2>&1 | \
    grep -c "^dn:" > /dev/null

end_time=$(date +%s%N)
total_ms=$(( (end_time - start_time) / 1000000 ))
avg_ms=$(( total_ms / 1000 ))
ops_per_sec=$(( 1000000 / avg_ms ))

echo "   Total time: ${total_ms} ms for 1000 queries"
echo "   Average: ${avg_ms} ms per query"  
echo "   Throughput: ${ops_per_sec} queries/sec"

# Test raw search performance
echo -e "\n2. Directory Scan Performance"
start_time=$(date +%s%N)
entry_count=$(ldapsearch -x -H ldap://localhost:389 -b "dc=example,dc=com" "(objectClass=*)" dn 2>/dev/null | grep -c "^dn:")
end_time=$(date +%s%N)
scan_ms=$(( (end_time - start_time) / 1000000 ))
echo "   Scanned $entry_count entries in ${scan_ms} ms"
echo "   Rate: $(( (entry_count * 1000) / scan_ms )) entries/sec"

# Test authentication performance with timing
echo -e "\n3. Authentication Performance (100 binds)"
total_auth=0
for i in {1..100}; do
    start=$(date +%s%N)
    ldapwhoami -x -H ldap://localhost:389 -D "uid=jdoe,ou=users,dc=example,dc=com" -w password123 >/dev/null 2>&1
    end=$(date +%s%N)
    auth_time=$(( (end - start) / 1000000 ))
    total_auth=$((total_auth + auth_time))
done
avg_auth=$((total_auth / 100))
echo "   Average bind time: ${avg_auth} ms"
echo "   Binds/sec: $((1000 / avg_auth))"

echo -e "\n================================="
echo "Performance Summary:"
if [ $avg_ms -lt 10 ]; then
    echo "⚡ LIGHTNING FAST - Excellent performance!"
elif [ $avg_ms -lt 50 ]; then
    echo "🚀 VERY FAST - Great performance!"
elif [ $avg_ms -lt 100 ]; then
    echo "✓ FAST - Good performance"
else
    echo "🐌 Could be faster"
fi