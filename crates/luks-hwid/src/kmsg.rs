use std::fs::{File, OpenOptions};
use std::io::Write;

/// Journal de boot : /dev/kmsg si disponible (initramfs), stderr sinon.
/// Chaque étape du keyscript et du ré-enrôlement passe par ici.
pub struct Log {
    kmsg: Option<File>,
}

impl Log {
    pub fn new() -> Self {
        Log {
            kmsg: OpenOptions::new().write(true).open("/dev/kmsg").ok(),
        }
    }

    fn write(&mut self, level: u8, msg: &str) {
        if let Some(f) = self.kmsg.as_mut() {
            // niveaux syslog : 3=err, 4=warn, 6=info
            let _ = writeln!(f, "<{level}>luks-hwid: {msg}");
        } else {
            let _ = writeln!(std::io::stderr(), "luks-hwid: {msg}");
        }
    }

    pub fn info(&mut self, msg: &str) {
        self.write(6, msg);
    }

    pub fn warn(&mut self, msg: &str) {
        self.write(4, msg);
    }

    pub fn err(&mut self, msg: &str) {
        self.write(3, msg);
    }
}
