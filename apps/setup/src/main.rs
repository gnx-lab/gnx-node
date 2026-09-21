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
    // WebView2 rejects file URLs in some installed/runtime contexts. Serve every
    // local asset from our private protocol instead; no browser or HTTP listener.
    let ui_root = std::fs::canonicalize(path)?
        .parent()
        .ok_or("Setup UI has no parent directory")?
        .to_path_buf();
    let event_loop = EventLoop::new();
    let window = WindowBuilder::new()
        .with_title("GnX Node Setup")
        .build(&event_loop)?;
    let webview = WebViewBuilder::new()
        .with_custom_protocol("gnx".into(), move |_, request: Request<Vec<u8>>| {
            handle_request(&ui_root, request)
        })
        .with_navigation_handler(|url| url.starts_with("gnx://"))
        .with_url("gnx://ui/index.html")
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
fn handle_request(
    ui_root: &std::path::Path,
    request: wry::http::Request<Vec<u8>>,
) -> wry::http::Response<std::borrow::Cow<'static, [u8]>> {
    use std::borrow::Cow;
    let uri = request.uri();
    let response = if uri.host() == Some("bridge") {
        ("application/json", handle_bridge(request.body()))
    } else if uri.host() == Some("ui") {
        let relative = uri.path().trim_start_matches('/');
        let allowed = matches!(relative, "index.html" | "styles.css" | "app.js");
        let path = ui_root.join(relative);
        if allowed && path.is_file() {
            let mime = if relative.ends_with(".css") {
                "text/css; charset=utf-8"
            } else if relative.ends_with(".js") {
                "text/javascript; charset=utf-8"
            } else {
                "text/html; charset=utf-8"
            };
            (mime, std::fs::read(path).unwrap_or_default())
        } else {
            ("text/plain; charset=utf-8", b"not found".to_vec())
        }
    } else {
        ("text/plain; charset=utf-8", b"forbidden".to_vec())
    };
    wry::http::Response::builder()
        .header("Content-Type", response.0)
        .header("X-Content-Type-Options", "nosniff")
        .body(Cow::Owned(response.1))
        .unwrap()
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
