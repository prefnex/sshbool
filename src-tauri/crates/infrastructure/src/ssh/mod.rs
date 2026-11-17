//! SSH connection manager (russh) — sessions, PTY, SFTP.

mod manager;

pub use manager::{ConnectionManager, ExecCapture, SftpEntry};
