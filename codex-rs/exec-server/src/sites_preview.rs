use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::net::TcpListener;
use std::os::fd::AsRawFd;

use codex_sandboxing::sites_preview::SITES_PREVIEW_LISTENER_FD_ENV_VAR;
use codex_sandboxing::sites_preview::SITES_PREVIEW_PORT;

/// Exec-server-owned browser ingress for one Sites preview process.
pub(crate) struct SitesPreviewListener {
    listener: TcpListener,
}

/// Error returned while preparing the fixed Sites preview ingress.
#[derive(Debug)]
pub(crate) enum SitesPreviewListenerError {
    PortInUse,
    Io(io::Error),
}

impl SitesPreviewListener {
    /// Binds the fixed browser-visible Sites preview port when requested.
    pub(crate) fn prepare(sites_preview: bool) -> Result<Option<Self>, SitesPreviewListenerError> {
        if !sites_preview {
            return Ok(None);
        }

        Self::bind(SITES_PREVIEW_PORT).map(Some)
    }

    /// Adds the inherited listener fd consumed by `codex-linux-sandbox`.
    pub(crate) fn add_to_child_env(&self, env: &mut HashMap<String, String>) {
        env.insert(
            SITES_PREVIEW_LISTENER_FD_ENV_VAR.to_string(),
            self.listener.as_raw_fd().to_string(),
        );
    }

    /// Returns the listener fd that the spawned sandbox helper must preserve.
    pub(crate) fn inherited_fd(&self) -> i32 {
        self.listener.as_raw_fd()
    }

    fn bind(port: u16) -> Result<Self, SitesPreviewListenerError> {
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).map_err(|error| {
            if error.kind() == io::ErrorKind::AddrInUse {
                SitesPreviewListenerError::PortInUse
            } else {
                SitesPreviewListenerError::Io(error)
            }
        })?;
        set_close_on_exec(listener.as_raw_fd())?;
        Ok(Self { listener })
    }
}

impl From<io::Error> for SitesPreviewListenerError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn set_close_on_exec(fd: libc::c_int) -> io::Result<()> {
    // SAFETY: `fd` comes from this process's live `TcpListener`.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `fd` comes from this process's live `TcpListener`.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_exports_inherited_fd_to_child_env() {
        let listener = SitesPreviewListener::bind(0).expect("bind Sites preview listener");
        let mut env = HashMap::new();

        listener.add_to_child_env(&mut env);

        assert_eq!(
            env.get(SITES_PREVIEW_LISTENER_FD_ENV_VAR),
            Some(&listener.inherited_fd().to_string())
        );
    }

    #[test]
    fn listener_keeps_close_on_exec_in_parent() {
        let listener = SitesPreviewListener::bind(0).expect("bind Sites preview listener");

        assert_ne!(fd_flags(listener.inherited_fd()) & libc::FD_CLOEXEC, 0);
    }

    fn fd_flags(fd: libc::c_int) -> libc::c_int {
        // SAFETY: `fd` comes from this test's live `TcpListener`.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0, "read fd flags: {}", io::Error::last_os_error());
        flags
    }
}
