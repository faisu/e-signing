use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let bundle_dir = manifest_dir.join("bundled-cas");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("ca_bundle_data.rs");

    println!("cargo:rerun-if-changed=bundled-cas");
    println!("cargo:rerun-if-changed=build.rs");

    let mut entries: Vec<String> = Vec::new();

    if bundle_dir.is_dir() {
        let mut paths: Vec<PathBuf> = fs::read_dir(&bundle_dir)
            .expect("read bundled-cas")
            .filter_map(|r| r.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .filter(|p| {
                p.extension()
                    .and_then(|e| e.to_str())
                    .map(|e| {
                        let e = e.to_ascii_lowercase();
                        e == "der" || e == "cer" || e == "crt"
                    })
                    .unwrap_or(false)
            })
            .collect();
        paths.sort();
        for path in paths {
            println!("cargo:rerun-if-changed={}", path.display());
            let abs = path.canonicalize().expect("canonicalize bundled-ca path");
            entries.push(format!("    include_bytes!({:?}),", abs.to_string_lossy()));
        }
    }

    let body = if entries.is_empty() {
        "pub static BUNDLED_CA_DERS: &[&[u8]] = &[];\n".to_string()
    } else {
        format!(
            "pub static BUNDLED_CA_DERS: &[&[u8]] = &[\n{}\n];\n",
            entries.join("\n")
        )
    };

    fs::write(&dest, body).expect("write ca_bundle_data.rs");
}
