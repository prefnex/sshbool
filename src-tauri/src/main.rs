#![windows_subsystem = "windows"]

fn main() {
    // Deep links reach an already-running instance through tauri-plugin-single-instance
    // (VULN-14: no world-writable handoff file in the home directory).
    sshbool_lib::run();
}
