#!/bin/bash
# Performance test for yamldap using ldapsearch

echo "YAMLDAP Performance Test"
echo "========================"
echo ""

# Function to measure time in milliseconds
measure_time() {
    local start=$(date +%s%N)
    "$@" >/dev/null 2>&1
    local end=$(date +%s%N)
    echo $(( (end - start) / 1000000 ))
}

# Warm up
echo "Warming up..."
for i in {1..10}; do
    ldapsearch -x -H ldap://localhost:389 -b "dc=example,dc=com" "(uid=jdoe)" >/dev/null 2>&1
done

# Test 1: Single user lookup
echo -e "\n1. Single User Lookup Test (100 iterations)"
total_time=0
for i in {1..100}; do
    time_ms=$(measure_time ldapsearch -x -H ldap://localhost:389 -b "dc=example,dc=com" "(uid=jdoe)")
    total_time=$((total_time + time_ms))
done
avg_time=$((total_time / 100))
echo "   Average time: ${avg_time} ms"
echo "   Operations/sec: $((1000 / (avg_time + 1)))"

# Test 2: Authenticated bind
echo -e "\n2. Authenticated Bind Test (100 iterations)"
total_time=0
for i in {1..100}; do
    time_ms=$(measure_time ldapsearch -x -H ldap://localhost:389 -D "uid=jdoe,ou=users,dc=example,dc=com" -w password123 -b "dc=example,dc=com" -s base)
    total_time=$((total_time + time_ms))
done
avg_time=$((total_time / 100))
echo "   Average time: ${avg_time} ms"
echo "   Operations/sec: $((1000 / (avg_time + 1)))"

# Test 3: Full directory search
echo -e "\n3. Full Directory Search Test (50 iterations)"
total_time=0
for i in {1..50}; do
    time_ms=$(measure_time ldapsearch -x -H ldap://localhost:389 -b "dc=example,dc=com" "(objectClass=*)")
    total_time=$((total_time + time_ms))
done
avg_time=$((total_time / 50))
echo "   Average time: ${avg_time} ms"
echo "   Operations/sec: $((1000 / (avg_time + 1)))"

# Test 4: Concurrent connections
echo -e "\n4. Concurrent Connection Test (10 parallel clients)"
start_time=$(date +%s%N)
for i in {1..10}; do
    (
        for j in {1..20}; do
            ldapsearch -x -H ldap://localhost:389 -b "dc=example,dc=com" "(uid=jdoe)" >/dev/null 2>&1
        done
    ) &
done
wait
end_time=$(date +%s%N)
total_ms=$(( (end_time - start_time) / 1000000 ))
echo "   Total time: ${total_ms} ms for 200 operations"
echo "   Throughput: $((200000 / total_ms)) ops/sec"

echo -e "\n========================"
echo "Performance Summary:"
if [ $avg_time -lt 50 ]; then
    echo "⚡ LIGHTNING FAST - Excellent performance!"
elif [ $avg_time -lt 100 ]; then
    echo "🚀 FAST - Good performance!"
else
    echo "✓ ACCEPTABLE - Decent performance"
fi