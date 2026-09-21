use gnx_control_protocol::{NodeState, Progress};
use std::{
    fs, io,
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub fn state_dir() -> PathBuf {
    if let Ok(p) = std::env::var("GNX_STATE_DIR") {
        return PathBuf::from(p);
    }
    if cfg!(windows) {
        std::env::var("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData"))
            .join(r"GnX\Node\state")
    } else {
        PathBuf::from("target/gnx-state")
    }
}
pub fn load() -> io::Result<Progress> {
    let journal = state_dir().join("progress.jsonl");
    if let Ok(text) = fs::read_to_string(&journal) {
        if let Some(progress) = text
            .lines()
            .rev()
            .find_map(|line| serde_json::from_str::<Progress>(line).ok())
        {
            return Ok(progress);
        }
    }
    let p = state_dir().join("progress.json");
    match fs::read(&p) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(initial()),
        Err(e) => Err(e),
    }
}
pub fn save(progress: &Progress) -> io::Result<()> {
    let dir = state_dir();
    fs::create_dir_all(&dir)?;
    let tmp = dir.join("progress.json.tmp");
    let dst = dir.join("progress.json");
    let safe = sanitize(progress);
    let bytes = serde_json::to_vec_pretty(&safe).map_err(io::Error::other)?;
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, dst).and_then(|_| {
        use std::io::Write;
        let mut journal = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("progress.jsonl"))?;
        serde_json::to_writer(&mut journal, &safe).map_err(io::Error::other)?;
        journal.write_all(b"\n")
    })
}

fn sanitize(progress: &Progress) -> Progress {
    let mut safe = progress.clone();
    safe.message = sanitize_text(&safe.message);
    safe.error_code = safe.error_code.map(|value| sanitize_text(&value));
    safe
}

fn sanitize_text(value: &str) -> String {
    let mut output = value.replace("tskey-auth-", "[redacted-key]-");
    for marker in ["password", "secret", "token"] {
        output = output.replace(marker, "[redacted]");
    }
    output.chars().take(1024).collect()
}
pub fn initial() -> Progress {
    Progress {
        operation_id: Uuid::nil(),
        sequence: 0,
        phase: "new".into(),
        state: NodeState::New,
        message: "Ready to begin GnX Node setup.".into(),
        error_code: None,
        retryable: false,
        requires_restart: false,
        percent: Some(0),
    }
}
pub fn sanitized_path(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("payload")
        .to_string()
}
