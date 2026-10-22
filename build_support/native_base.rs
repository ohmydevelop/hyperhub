//! Fingerprint the resident native implementation, independently of replaceable
//! Engine processing. Parsing removes comments, formatting and test-only items.
use quote::ToTokens;
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const MARKER_PREFIX: &str = "hyperhub-native-base-v1:";

fn test_only(item: &syn::Item) -> bool {
    let attrs = match item {
        syn::Item::Const(i) => &i.attrs,
        syn::Item::Enum(i) => &i.attrs,
        syn::Item::ExternCrate(i) => &i.attrs,
        syn::Item::Fn(i) => &i.attrs,
        syn::Item::ForeignMod(i) => &i.attrs,
        syn::Item::Impl(i) => &i.attrs,
        syn::Item::Macro(i) => &i.attrs,
        syn::Item::Mod(i) => &i.attrs,
        syn::Item::Static(i) => &i.attrs,
        syn::Item::Struct(i) => &i.attrs,
        syn::Item::Trait(i) => &i.attrs,
        syn::Item::TraitAlias(i) => &i.attrs,
        syn::Item::Type(i) => &i.attrs,
        syn::Item::Union(i) => &i.attrs,
        syn::Item::Use(i) => &i.attrs,
        _ => return false,
    };
    attrs.iter().any(|attribute| {
        matches!(&attribute.meta, syn::Meta::List(list)
        if list.path.is_ident("cfg") && list.tokens.to_string() == "test")
    })
}
fn strip_tests(items: &mut Vec<syn::Item>) {
    items.retain(|item| !test_only(item));
    for item in items {
        if let syn::Item::Mod(module) = item {
            if let Some((_, items)) = &mut module.content {
                strip_tests(items);
            }
        }
    }
}
pub fn normalized(source: &str) -> io::Result<String> {
    let mut file = syn::parse_file(source).map_err(io::Error::other)?;
    strip_tests(&mut file.items);
    Ok(without_docs(file.into_token_stream()).to_string())
}
fn without_docs(stream: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
    use proc_macro2::{Delimiter, Group, TokenTree};
    let mut tokens = stream.into_iter().peekable();
    let mut output = proc_macro2::TokenStream::new();
    while let Some(token) = tokens.next() {
        if matches!(&token, TokenTree::Punct(p) if p.as_char() == '#') {
            let mut look = tokens.clone();
            let inner = matches!(look.peek(), Some(TokenTree::Punct(p)) if p.as_char() == '!');
            if inner {
                look.next();
            }
            if matches!(look.next(), Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Bracket
                && matches!(group.stream().into_iter().next(), Some(TokenTree::Ident(id)) if id == "doc"))
            {
                if inner {
                    tokens.next();
                }
                tokens.next();
                continue;
            }
        }
        output.extend([match token {
            TokenTree::Group(group) => {
                TokenTree::Group(Group::new(group.delimiter(), without_docs(group.stream())))
            }
            token => token,
        }]);
    }
    output
}
fn collect(directory: &Path, os: &str, paths: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            let name = entry.file_name();
            if (os == "windows" && name == "unix_gum") || (os != "windows" && name == "windows_gum")
            {
                continue;
            }
            collect(&path, os, paths)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "engine_tests.rs" || name == "tests.rs" || name.ends_with("_tests.rs") {
                continue;
            }
            paths.push(path);
        }
    }
    Ok(())
}
pub fn fingerprint(root: &Path, target: &str, os: &str) -> io::Result<String> {
    let mut paths = Vec::new();
    collect(&root.join("crates/hyperhub-agent-core/src"), os, &mut paths)?;
    collect(
        &root.join("crates/hyperhub-cli/src/platform"),
        os,
        &mut paths,
    )?;
    paths.retain(|path| {
        let text = path.to_string_lossy().replace('\\', "/");
        !(os == "windows" && text.contains("/platform/linux/"))
            && !(os != "windows" && text.ends_with("/platform/windows.rs"))
    });
    for file in [
        "crates/hyperhub-agent-core/build.rs",
        "crates/hyperhub-runtime/src/abi.rs",
        "crates/hyperhub-runtime/src/artifact.rs",
        "crates/hyperhub-runtime/src/generation.rs",
        "crates/hyperhub-runtime/src/native.rs",
        "crates/hyperhub-engine/src/host.rs",
        "crates/hyperhub-engine/src/bootstrap.rs",
        "crates/hyperhub-engine/src/management.rs",
        // This file also contains Host-side C ABI request/response helpers.
        "crates/hyperhub-engine/src/lib.rs",
        "crates/hyperhub-engine/src/contract.rs",
    ] {
        paths.push(root.join(file));
    }
    hash_paths(root, target, MARKER_PREFIX, paths)
}

/// Shared ingress/authority modules are deliberately conservative: changes to
/// them require a resident Serve restart. Pure worker business modules remain
/// outside this set, as do replaceable Engine implementations.
pub fn serve_fingerprint(root: &Path, target: &str, os: &str) -> io::Result<String> {
    let mut paths = Vec::new();
    for directory in [
        "crates/hyperhub-core/src/upgrade",
        "crates/hyperhub-core/src/release",
        "crates/hyperhub-core/src/forward/manager",
        "crates/hyperhub-core/src/forward/wire",
        "crates/hyperhub-core/src/socks",
    ] {
        collect(&root.join(directory), os, &mut paths)?;
    }
    for file in [
        "control.rs",
        "session.rs",
        "engine_hosts.rs",
        "engine_host_exit.rs",
        "upgrade/mod.rs",
        "upgrade/driver.rs",
        "release.rs",
        "socks.rs",
        "runtime.rs",
        "config.rs",
        "config_store.rs",
        "audit.rs",
        "trust.rs",
        "client_proxy.rs",
        "http/authority.rs",
        "forward/manager.rs",
        "forward/wire.rs",
        "forward/authority.rs",
        "forward/cancellation.rs",
        "forward/deadline.rs",
        "forward/protocol.rs",
    ] {
        paths.push(root.join("crates/hyperhub-core/src").join(file));
    }
    hash_paths(root, target, "hyperhub-serve-base-v1:", paths)
}

fn hash_paths(
    root: &Path,
    target: &str,
    purpose: &str,
    mut paths: Vec<PathBuf>,
) -> io::Result<String> {
    paths.sort();
    paths.dedup();
    let mut hash = Sha256::new();
    hash.update(purpose);
    hash.update(target.as_bytes());
    for path in paths {
        println!("cargo:rerun-if-changed={}", path.display());
        let relative = path.strip_prefix(root).map_err(io::Error::other)?;
        let relative = relative.to_string_lossy().replace('\\', "/");
        let source = normalized(&fs::read_to_string(&path)?)?;
        hash.update((relative.len() as u64).to_le_bytes());
        hash.update(relative.as_bytes());
        hash.update((source.len() as u64).to_le_bytes());
        hash.update(source.as_bytes());
    }
    Ok(hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
