use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=src/wrapper.c");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    cc::Build::new().file("src/wrapper.c").compile("wrapper");
    pkg_config::Config::new().probe("zlib").unwrap();
    std::fs::write(out.join("version.rs"), "pub const V: &str = \"1\";").unwrap();
}
