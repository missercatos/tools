#![forbid(unsafe_code)]

use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread::JoinHandle;
use std::process::Command;

/// 事件驱动弹窗线程：阻塞在 recv()，闲置 0 CPU；命中时才被唤醒
pub fn spawn() -> (Sender<String>, JoinHandle<()>) {
    let (tx, rx): (Sender<String>, Receiver<String>) = channel();
    let handle = std::thread::spawn(move || {
        for msg in rx {
            eprintln!("[notify] {msg}");
            let _ = Command::new("notify-send")
                .arg("-u")
                .arg("critical")
                .arg("brute")
                .arg(truncate(&msg, 120))
                .status();
        }
    });
    (tx, handle)
}

fn truncate(s: &str, max: usize) -> String {
    let s: String = s.chars().take(max).collect();
    s.replace('\n', " ")
}