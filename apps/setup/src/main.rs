mod agent_client;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ui = locate_ui();
    if !ui.exists() {
        return Err(format!("Setup UI asset missing: {}", ui.display()).into());
    }
    #[cfg(windows)]
    launch_local_ui(&ui)?;
    Ok(())
}

fn locate_ui() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("GNX_SETUP_UI") {
        return path.into();
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.join(r"ui\index.html")))
        .unwrap_or_else(|| std::path::PathBuf::from("apps/setup/ui/index.html"))
}

#[cfg(windows)]
fn launch_local_ui(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::borrow::Cow;
    use tao::{
        event::{Event, WindowEvent},
        event_loop::{ControlFlow, EventLoop},
        window::WindowBuilder,
    };
    use wry::{
        http::{Request, Response},
        WebViewBuilder,
    };
    let ui_path = std::fs::canonicalize(path)?;
    let ui_url = format!("file:///{}", ui_path.to_string_lossy().replace('\\', "/"));
    let allowed_url = ui_url.clone();
    let event_loop = EventLoop::new();
    let window = WindowBuilder::new()
        .with_title("GnX Node Setup")
        .build(&event_loop)?;
    let webview = WebViewBuilder::new()
        .with_custom_protocol("gnx".into(), |_, request: Request<Vec<u8>>| {
            Response::builder()
                .header("Content-Type", "application/json")
                .header("Access-Control-Allow-Origin", "*")
                .body(Cow::Owned(handle_bridge(request.body())))
                .unwrap()
        })
        .with_navigation_handler(move |url| url == allowed_url || url.starts_with("gnx://"))
        .with_url(&ui_url)
        .build(&window)?;
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            *control_flow = ControlFlow::Exit;
        }
        let _ = &webview;
    });
    Ok(())
}

#[cfg(windows)]
fn handle_bridge(body: &[u8]) -> Vec<u8> {
    use gnx_control_protocol::{Operation, Request, PROTOCOL_VERSION};
    use serde::Deserialize;
    use uuid::Uuid;
    #[derive(Deserialize)]
    struct BridgeRequest {
        method: String,
        tailscale_auth_key: Option<String>,
    }
    let result = (|| -> Result<Vec<u8>, String> {
        let bridge: BridgeRequest = serde_json::from_slice(body).map_err(|e| e.to_string())?;
        let operation = match bridge.method.as_str() {
            "GetProgress" => Operation::GetProgress,
            "Provision" => Operation::Provision,
            "JoinMesh" => Operation::JoinMesh,
            "Retry" => Operation::Retry,
            "Cancel" => Operation::Cancel,
            "Deprovision" => Operation::Deprovision,
            _ => return Err("unsupported bridge method".into()),
        };
        if operation != Operation::JoinMesh && bridge.tailscale_auth_key.is_some() {
            return Err("credentials are accepted only by JoinMesh".into());
        }
        let response = agent_client::request(&Request {
            version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            operation,
            tailscale_auth_key: bridge.tailscale_auth_key,
        })
        .map_err(|e| e.to_string())?;
        serde_json::to_vec(&response).map_err(|e| e.to_string())
    })();
    result.unwrap_or_else(|error| {
        serde_json::to_vec(&serde_json::json!({"error": error})).unwrap_or_default()
    })
}
