use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use uuid::Uuid;

#[derive(Serialize)]
struct RpcRequest { id: String, method: String, params: Value }

#[derive(Deserialize)]
struct RpcError { code: String, message: String }

#[derive(Deserialize)]
struct RpcResponse { id: Option<String>, result: Option<Value>, error: Option<RpcError> }

struct BackendProcess { _child: Child, stdin: ChildStdin, stdout: BufReader<ChildStdout> }

#[derive(Clone)]
pub struct SidecarManager { inner: Arc<Mutex<Option<BackendProcess>>> }

impl SidecarManager {
    pub fn new() -> Self { Self { inner: Arc::new(Mutex::new(None)) } }

    fn resolve_sidecar_binary() -> Option<PathBuf> {
        let dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
        #[cfg(target_os = "windows")]
        let candidate = dir.join("ppstudio-backend.exe");
        #[cfg(not(target_os = "windows"))]
        let candidate = dir.join("ppstudio-backend");
        if candidate.metadata().map(|m| m.len() > 0).unwrap_or(false) { Some(candidate) } else { None }
    }

    async fn spawn_backend() -> Result<BackendProcess, String> {
        let mut cmd = if let Some(bin) = Self::resolve_sidecar_binary() {
            Command::new(bin)
        } else {
            let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
            let mut c = Command::new("python3");
            c.arg("-m").arg("app.rpc").current_dir(repo_root);
            c
        };
        let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).kill_on_drop(true)
            .spawn().map_err(|e| format!("Failed to start Python engine sidecar: {e}"))?;
        let stdin = child.stdin.take().ok_or("Missing sidecar stdin")?;
        let stdout = child.stdout.take().ok_or("Missing sidecar stdout")?;
        Ok(BackendProcess { _child: child, stdin, stdout: BufReader::new(stdout) })
    }

    pub async fn call(&self, method: String, params: Value) -> Result<Value, String> {
        let mut guard = self.inner.lock().await;
        if guard.is_none() { *guard = Some(Self::spawn_backend().await?); }
        let proc = guard.as_mut().unwrap();
        let req_id = Uuid::new_v4().to_string();
        let mut line = serde_json::to_string(&RpcRequest { id: req_id.clone(), method, params }).map_err(|e| e.to_string())?;
        line.push('\n');
        if let Err(e) = proc.stdin.write_all(line.as_bytes()).await { *guard = None; return Err(format!("IPC write error: {e}")); }
        let _ = proc.stdin.flush().await;
        let mut resp_line = String::new();
        match timeout(Duration::from_secs(30), proc.stdout.read_line(&mut resp_line)).await {
            Err(_) => { *guard = None; Err("Backend operation timed out after 30s".into()) }
            Ok(Err(e)) => { *guard = None; Err(format!("IPC read error: {e}")) }
            Ok(Ok(0)) => { *guard = None; Err("Python backend exited unexpectedly".into()) }
            Ok(Ok(_)) => {
                let parsed: RpcResponse = serde_json::from_str(&resp_line).map_err(|e| format!("Invalid backend JSON: {e}"))?;
                if parsed.id.as_deref() != Some(req_id.as_str()) { return Err("Mismatched IPC response ID".into()); }
                if let Some(err) = parsed.error { Err(format!("{}: {}", err.code, err.message)) }
                else { Ok(parsed.result.unwrap_or(Value::Null)) }
            }
        }
    }
}
