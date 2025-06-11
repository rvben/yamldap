#!/usr/bin/env python3
"""
Performance stress test for yamldap server
"""

import ldap
import time
import threading
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed

def test_bind_performance(host='localhost', port=389, iterations=100):
    """Test bind operation performance"""
    times = []
    
    for i in range(iterations):
        start = time.time()
        try:
            conn = ldap.initialize(f"ldap://{host}:{port}")
            conn.simple_bind_s("uid=jdoe,ou=users,dc=example,dc=com", "password123")
            conn.unbind_s()
            elapsed = time.time() - start
            times.append(elapsed * 1000)  # Convert to ms
        except Exception as e:
            print(f"Bind error: {e}")
    
    return times

def test_search_performance(host='localhost', port=389, iterations=100):
    """Test search operation performance"""
    conn = ldap.initialize(f"ldap://{host}:{port}")
    conn.simple_bind_s("", "")
    
    times = []
    for i in range(iterations):
        start = time.time()
        try:
            results = conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, "(objectClass=*)")
            elapsed = time.time() - start
            times.append(elapsed * 1000)  # Convert to ms
        except Exception as e:
            print(f"Search error: {e}")
    
    conn.unbind_s()
    return times

def test_concurrent_connections(host='localhost', port=389, num_threads=10, operations_per_thread=10):
    """Test concurrent connection handling"""
    def worker():
        times = []
        for _ in range(operations_per_thread):
            start = time.time()
            try:
                conn = ldap.initialize(f"ldap://{host}:{port}")
                conn.simple_bind_s("uid=jdoe,ou=users,dc=example,dc=com", "password123")
                results = conn.search_s("ou=users,dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=jdoe)")
                conn.unbind_s()
                elapsed = time.time() - start
                times.append(elapsed * 1000)
            except Exception as e:
                print(f"Concurrent test error: {e}")
        return times
    
    start_time = time.time()
    all_times = []
    
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker) for _ in range(num_threads)]
        
        for future in as_completed(futures):
            all_times.extend(future.result())
    
    total_time = time.time() - start_time
    return all_times, total_time

def print_stats(times, operation_name):
    """Print performance statistics"""
    if times:
        print(f"\n{operation_name} Performance:")
        print(f"  Operations: {len(times)}")
        print(f"  Min: {min(times):.2f} ms")
        print(f"  Max: {max(times):.2f} ms")
        print(f"  Mean: {statistics.mean(times):.2f} ms")
        print(f"  Median: {statistics.median(times):.2f} ms")
        if len(times) > 1:
            print(f"  Std Dev: {statistics.stdev(times):.2f} ms")
        print(f"  Total: {sum(times):.2f} ms")
        print(f"  Ops/sec: {1000 / statistics.mean(times):.2f}")

def main():
    print("YAMLDAP Performance Test")
    print("========================\n")
    
    # Warm up
    print("Warming up...")
    test_bind_performance(iterations=10)
    
    # Test bind performance
    print("\nTesting bind operations...")
    bind_times = test_bind_performance(iterations=100)
    print_stats(bind_times, "Bind")
    
    # Test search performance
    print("\nTesting search operations...")
    search_times = test_search_performance(iterations=100)
    print_stats(search_times, "Search")
    
    # Test concurrent connections
    print("\nTesting concurrent connections...")
    threads = 20
    ops_per_thread = 50
    concurrent_times, total_time = test_concurrent_connections(
        num_threads=threads, 
        operations_per_thread=ops_per_thread
    )
    print_stats(concurrent_times, "Concurrent Operations")
    print(f"  Total operations: {threads * ops_per_thread}")
    print(f"  Total time: {total_time:.2f} seconds")
    print(f"  Overall throughput: {(threads * ops_per_thread) / total_time:.2f} ops/sec")
    
    # Performance summary
    print("\n" + "="*50)
    print("PERFORMANCE SUMMARY")
    print("="*50)
    
    if bind_times and search_times:
        avg_bind = statistics.mean(bind_times)
        avg_search = statistics.mean(search_times)
        
        print(f"Average bind time: {avg_bind:.2f} ms")
        print(f"Average search time: {avg_search:.2f} ms")
        print(f"Bind operations/sec: {1000 / avg_bind:.2f}")
        print(f"Search operations/sec: {1000 / avg_search:.2f}")
        
        # Performance rating
        if avg_bind < 5 and avg_search < 10:
            print("\n⚡ LIGHTNING FAST - Excellent performance!")
        elif avg_bind < 10 and avg_search < 20:
            print("\n🚀 FAST - Good performance!")
        elif avg_bind < 20 and avg_search < 50:
            print("\n✓ ACCEPTABLE - Decent performance")
        else:
            print("\n⚠️  SLOW - Performance needs improvement")

if __name__ == "__main__":
    main()