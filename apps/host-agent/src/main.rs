mod control_pipe;
mod provisioning;
mod state;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        // The installed binary is a real SCM service. GNX_CONSOLE=1 is an explicit
        // developer/diagnostic escape hatch for running the same pipe server in a console.
        if std::env::var_os("GNX_CONSOLE").is_some() {
            return control_pipe::run();
        }
        return service::run().map_err(|e| e.into());
    }
    #[cfg(not(windows))]
    control_pipe::run()
}

#[cfg(windows)]
mod service {
    use super::control_pipe;
    use std::ffi::OsString;
    use std::sync::mpsc;
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
        let _ = stop_rx.recv();
        control_pipe::request_stop();
        let _ = server.join();
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
