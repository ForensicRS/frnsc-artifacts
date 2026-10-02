//! The generated catalog against the upstream YAML it came from, and against the
//! `forensic-rs` expansion rules.

use std::borrow::Cow;

use forensic_rs::catalog::{
    expand, ArtifactCatalog, ArtifactDefinition, ArtifactSource, Os, Separator,
};
use forensic_rs::core::path::FPathBuf;
use forensic_rs::host_profile::HostProfile;
use forensic_rs::provenance::{Acquisition, ProvenanceStore, Recovery, SourceKey, Tracked};
use forensic_rs::traits::registry::windows::UserProfile;
use frnsc_artifacts::{
    output_artifact, CATALOG, DEFINITION_COUNT, KB_COMMIT, KB_UPSTREAM_COMMIT, LOCAL_DEFINITIONS,
    MAPPED_DEFINITIONS,
};

fn get(name: &str) -> &'static ArtifactDefinition {
    CATALOG
        .get(name)
        .unwrap_or_else(|| panic!("{name} not in the catalog"))
}

fn file_paths(def: &ArtifactDefinition) -> Vec<(&str, Separator)> {
    def.sources
        .iter()
        .filter_map(|entry| match &entry.source {
            ArtifactSource::File { paths, separator } => Some((paths, *separator)),
            _ => None,
        })
        .flat_map(|(paths, sep)| paths.iter().map(move |p| (p.as_ref(), sep)))
        .collect()
}

#[test]
fn has_every_upstream_definition() {
    assert_eq!(DEFINITION_COUNT, 736);
    assert_eq!(CATALOG.len(), DEFINITION_COUNT);
    assert_eq!(CATALOG.iter().count(), DEFINITION_COUNT);
}

/// The Apache-2.0 notice for the modified definitions: each local one is in the catalog, and the
/// pin says it is not upstream.
#[test]
fn local_definitions_are_listed_against_their_upstream_base() {
    assert_eq!(
        LOCAL_DEFINITIONS,
        [
            "BraveBrowserHistoryDatabaseFile",
            "DockerContainerHostConfig",
            "KubernetesContainerLogSymlinks",
            "VivaldiBrowserHistoryDatabaseFile",
        ]
    );
    for name in LOCAL_DEFINITIONS {
        assert!(CATALOG.get(name).is_some(), "{name}");
    }
    assert_ne!(KB_COMMIT, KB_UPSTREAM_COMMIT);
}

#[test]
fn names_and_aliases_are_unique_and_indexed() {
    CATALOG.validate().unwrap();
}

#[test]
fn every_group_member_exists() {
    assert_eq!(
        CATALOG.dangling_group_members(),
        Vec::<(Cow<'static, str>, Cow<'static, str>)>::new()
    );
}

#[test]
fn every_definition_expands_without_cycles_or_unknown_placeholders() {
    let host = HostProfile::default();
    let mut problems = Vec::new();
    for def in CATALOG.iter() {
        let oses: Vec<Os> = if def.supported_os.is_empty() {
            vec![Os::Windows, Os::Linux, Os::Darwin]
        } else {
            def.supported_os.to_vec()
        };
        for os in oses {
            let e = expand(def, &CATALOG, &host, os);
            for note in e.notes.iter().filter(|n| n.contains("cycle")) {
                problems.push(format!("{} on {os}: {note}", def.name));
            }
            for u in e
                .unresolved
                .iter()
                .filter(|u| !u.reason.contains("live host only"))
            {
                problems.push(format!("{} on {os}: {} ({})", def.name, u.source, u.reason));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "{} problems:\n{}",
        problems.len(),
        problems.join("\n")
    );
}

#[test]
fn amcache_matches_the_yaml() {
    let def = get("WindowsAMCacheHveFile");
    assert_eq!(
        file_paths(def),
        vec![
            (
                r"%%environ_systemroot%%\AppCompat\Programs\Amcache.hve",
                Separator::Backslash
            ),
            (
                r"%%environ_systemroot%%\AppCompat\Programs\Amcache.hve.LOG1",
                Separator::Backslash
            ),
            (
                r"%%environ_systemroot%%\AppCompat\Programs\Amcache.hve.LOG2",
                Separator::Backslash
            ),
        ]
    );
    assert_eq!(def.supported_os.as_ref(), &[Os::Windows]);
    assert_eq!(
        def.doc,
        "The AMCache file, stored in the Windows NT Registry file format."
    );
    assert_eq!(
        def.urls.as_ref(),
        &[Cow::Borrowed(
            "https://artifacts-kb.readthedocs.io/en/latest/sources/windows/AMCache.html"
        )]
    );
}

#[test]
fn prefetch_matches_the_yaml() {
    let def = get("WindowsPrefetchFiles");
    assert_eq!(
        file_paths(def),
        vec![(
            r"%%environ_systemroot%%\Prefetch\*.pf",
            Separator::Backslash
        )]
    );
}

#[test]
fn security_event_log_matches_the_yaml() {
    let def = get("WindowsXMLEventLogSecurity");
    assert_eq!(
        file_paths(def),
        vec![(
            r"%%environ_systemroot%%\System32\winevt\Logs\Security.evtx",
            Separator::Backslash
        )]
    );
}

#[test]
fn looks_up_aliases() {
    let (def, alias) = CATALOG
        .iter()
        .find_map(|d| d.aliases.first().map(|a| (d, a)))
        .expect("the KB has aliases");
    assert_eq!(CATALOG.get(alias).unwrap().name, def.name);
}

#[test]
fn registry_value_pairs_keep_key_and_value() {
    let def = get("WindowsActionCenterSettings");
    let ArtifactSource::RegistryValue { pairs } = &def.sources[0].source else {
        panic!("expected a REGISTRY_VALUE source");
    };
    assert_eq!(pairs.len(), 4);
    assert_eq!(
        pairs[2].key,
        r"HKEY_USERS\%%users.sid%%\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance"
    );
    assert_eq!(pairs[2].value, "Enabled");
}

#[test]
fn user_registry_files_expand_per_user() {
    let store = ProvenanceStore::new();
    let source = store.register_source(SourceKey::Synthetic("test".to_string()));
    let mint = || source.mint(Acquisition::ImageRead, Recovery::Allocated);
    let users = vec![
        UserProfile {
            sid: "S-1-5-21-1-2-3-1001".to_string(),
            profile_path: FPathBuf::from(r"C:\Users\alice"),
            name: Some("alice".to_string()),
        },
        UserProfile {
            sid: "S-1-5-21-1-2-3-1002".to_string(),
            profile_path: FPathBuf::from(r"C:\Users\bob"),
            name: Some("bob".to_string()),
        },
    ];
    let host = HostProfile {
        system_root: Some(Tracked::new(FPathBuf::from(r"C:\Windows"), mint())),
        users: Some(Tracked::new(users, mint())),
        ..HostProfile::default()
    };

    let e = expand(
        get("WindowsUserRegistryFiles"),
        &CATALOG,
        &host,
        Os::Windows,
    );

    let ntuser: Vec<(&str, Option<&str>)> = e
        .globs
        .iter()
        .filter(|g| g.pattern.ends_with(r"\NTUSER.DAT"))
        .map(|g| (g.pattern.as_str(), g.sid.as_deref()))
        .collect();
    assert_eq!(
        ntuser,
        vec![
            (r"\Users\alice\NTUSER.DAT", Some("S-1-5-21-1-2-3-1001")),
            (r"\Users\bob\NTUSER.DAT", Some("S-1-5-21-1-2-3-1002")),
        ]
    );
    assert!(e.globs.iter().all(|g| g.sid.is_some()), "{:?}", e.globs);
}

#[test]
fn every_mapped_definition_exists() {
    for name in MAPPED_DEFINITIONS {
        assert!(
            CATALOG.get(name).is_some(),
            "{name} is mapped but not in the catalog"
        );
        assert!(
            output_artifact(name).is_some(),
            "{name} is listed but not mapped"
        );
    }
    assert!(output_artifact("NoSuchDefinition").is_none());
}
