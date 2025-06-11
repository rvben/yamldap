use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::collections::HashMap;
use yamldap::directory::{storage::SearchScope, Directory};
use yamldap::ldap::filters::parse_ldap_filter;
use yamldap::yaml::{YamlDirectory, YamlEntry, YamlSchema};

fn create_test_directory(num_users: usize) -> Directory {
    let mut entries = vec![
        YamlEntry {
            dn: "dc=example,dc=com".to_string(),
            object_class: vec!["top".to_string(), "domain".to_string()],
            attributes: {
                let mut attrs = HashMap::new();
                attrs.insert(
                    "dc".to_string(),
                    serde_yaml::Value::String("example".to_string()),
                );
                attrs
            },
        },
        YamlEntry {
            dn: "ou=users,dc=example,dc=com".to_string(),
            object_class: vec!["top".to_string(), "organizationalUnit".to_string()],
            attributes: {
                let mut attrs = HashMap::new();
                attrs.insert(
                    "ou".to_string(),
                    serde_yaml::Value::String("users".to_string()),
                );
                attrs
            },
        },
    ];

    // Add users
    for i in 0..num_users {
        entries.push(YamlEntry {
            dn: format!("uid=user{},ou=users,dc=example,dc=com", i),
            object_class: vec![
                "top".to_string(),
                "person".to_string(),
                "inetOrgPerson".to_string(),
            ],
            attributes: {
                let mut attrs = HashMap::new();
                attrs.insert(
                    "uid".to_string(),
                    serde_yaml::Value::String(format!("user{}", i)),
                );
                attrs.insert(
                    "cn".to_string(),
                    serde_yaml::Value::String(format!("User {}", i)),
                );
                attrs.insert(
                    "sn".to_string(),
                    serde_yaml::Value::String(format!("Surname{}", i)),
                );
                attrs.insert(
                    "mail".to_string(),
                    serde_yaml::Value::String(format!("user{}@example.com", i)),
                );
                attrs.insert(
                    "userPassword".to_string(),
                    serde_yaml::Value::String("password123".to_string()),
                );
                attrs
            },
        });
    }

    let yaml_dir = YamlDirectory {
        directory: yamldap::yaml::schema::DirectoryConfig {
            base_dn: "dc=example,dc=com".to_string(),
        },
        schema: None,
        entries,
    };

    Directory::from_yaml(yaml_dir, YamlSchema::default())
}

fn benchmark_entry_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("entry_lookup");

    for size in [100, 1000, 10000].iter() {
        let dir = create_test_directory(*size);

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| dir.get_entry(black_box("uid=user500,ou=users,dc=example,dc=com")));
        });
    }

    group.finish();
}

fn benchmark_search_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("search_all");

    for size in [100, 1000, 10000].iter() {
        let dir = create_test_directory(*size);

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                dir.search_entries(
                    black_box("dc=example,dc=com"),
                    SearchScope::WholeSubtree,
                    |_| true,
                )
            });
        });
    }

    group.finish();
}

fn benchmark_filter_search(c: &mut Criterion) {
    let mut group = c.benchmark_group("filter_search");

    for size in [100, 1000, 10000].iter() {
        let dir = create_test_directory(*size);
        let filter = parse_ldap_filter("(uid=user500)").unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                dir.search_entries(
                    black_box("dc=example,dc=com"),
                    SearchScope::WholeSubtree,
                    |entry| filter.matches(entry),
                )
            });
        });
    }

    group.finish();
}

fn benchmark_auth_lookup(c: &mut Criterion) {
    let dir = create_test_directory(10000);

    c.bench_function("auth_user_lookup", |b| {
        b.iter(|| {
            let dn = black_box("uid=user5000,ou=users,dc=example,dc=com");
            if let Some(entry) = dir.get_entry(dn) {
                entry.get_attribute("userPassword");
            }
        });
    });
}

criterion_group!(
    benches,
    benchmark_entry_lookup,
    benchmark_search_all,
    benchmark_filter_search,
    benchmark_auth_lookup
);
criterion_main!(benches);
