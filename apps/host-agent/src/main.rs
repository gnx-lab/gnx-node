mod ca;
mod control_pipe;
mod dedicated_account;
mod linux_node;
mod provisioning;
mod secret_store;
mod state;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        // The installed binary is a real SCM service. GNX_CONSOLE=1 is an explicit
        // developer/diagnostic escape hatch for running the same pipe server in a console.
        if std::env::var_os("GNX_CONSOLE").is_some() {
            return control_pipe::run();
        }
        service::run().map_err(|e| e.into())
    }
    #[cfg(not(windows))]
    control_pipe::run()
}

#[cfg(windows)]
mod service {
    use super::control_pipe;
    use std::ffi::OsString;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service, service_dispatcher, Result};

    define_windows_service!(ffi_service_main, service_main);

    pub fn run() -> Result<()> {
        service_dispatcher::start("GnXHostAgent", ffi_service_main)
    }

    fn service_main(_arguments: Vec<OsString>) {
        let (stop_tx, stop_rx) = mpsc::channel();
        let event_handler = move |event| match event {
            service::ServiceControl::Stop => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            service::ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let status_handle = match service_control_handler::register("GnXHostAgent", event_handler) {
            Ok(handle) => handle,
            Err(_) => return,
        };
        let _ = status_handle.set_service_status(service::ServiceStatus {
            service_type: service::ServiceType::OWN_PROCESS,
            current_state: service::ServiceState::Running,
            controls_accepted: service::ServiceControlAccept::STOP,
            exit_code: service::ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        });
        let server = std::thread::spawn(|| control_pipe::run().map_err(|e| e.to_string()));
        // WSL intentionally shuts a distro down when its last Windows-side
        // client exits, even while systemd units are active. Keep one harmless
        // client attached so the private DNS and HTTPS endpoints stay online.
        let stop_keepalive = Arc::new(AtomicBool::new(false));
        let keepalive_flag = Arc::clone(&stop_keepalive);
        let keepalive = std::thread::spawn(move || {
            let args = vec![
                "--distribution".into(),
                crate::linux_node::DISTRO_NAME.into(),
                "--".into(),
                "/bin/sleep".into(),
                "5".into(),
            ];
            while !keepalive_flag.load(Ordering::Relaxed) {
                if crate::dedicated_account::run_wsl_as_windows_identity(&args).is_err() {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
            }
        });
        // Reuse the canonical verifier instead of inventing browser-side
        // health checks. This is a thread of the existing host service, not a
        // new network service or a browser control channel.
        let status_flag = Arc::clone(&stop_keepalive);
        let status_monitor = std::thread::spawn(move || {
            while !status_flag.load(Ordering::Relaxed) {
                let _ = crate::state::refresh_app_status();
                for _ in 0..15 {
                    if status_flag.load(Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            }
        });
        let _ = stop_rx.recv();
        stop_keepalive.store(true, Ordering::Relaxed);
        let _ = status_handle.set_service_status(service::ServiceStatus {
            service_type: service::ServiceType::OWN_PROCESS,
            current_state: service::ServiceState::StopPending,
            controls_accepted: service::ServiceControlAccept::empty(),
            exit_code: service::ServiceExitCode::Win32(0),
            checkpoint: 1,
            wait_hint: std::time::Duration::from_secs(10),
            process_id: None,
        });
        control_pipe::request_stop();
        let _ = server.join();
        let _ = keepalive.join();
        let _ = status_monitor.join();
        let _ = status_handle.set_service_status(service::ServiceStatus {
            service_type: service::ServiceType::OWN_PROCESS,
            current_state: service::ServiceState::Stopped,
            controls_accepted: service::ServiceControlAccept::empty(),
            exit_code: service::ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        });
    }
}
