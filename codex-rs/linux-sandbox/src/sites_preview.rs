use std::io;
use std::net::Ipv4Addr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::os::fd::FromRawFd;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use codex_sandboxing::sites_preview::SITES_PREVIEW_LISTENER_FD_ENV_VAR;
use codex_sandboxing::sites_preview::SITES_PREVIEW_PORT;

const LOCAL_SERVER_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const LOCAL_SERVER_CONNECT_RETRY_DELAY: Duration = Duration::from_millis(25);
const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONCURRENT_CONNECTIONS: usize = 16;

pub(crate) fn take_sites_preview_listener_fd_from_env() -> io::Result<Option<libc::c_int>> {
    let raw_fd = match std::env::var(SITES_PREVIEW_LISTENER_FD_ENV_VAR) {
        Ok(raw_fd) => raw_fd,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(error) => return Err(io::Error::other(error)),
    };
    let listener_fd = raw_fd.parse::<libc::c_int>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid Sites preview listener fd `{raw_fd}`: {error}"),
        )
    })?;
    if listener_fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid Sites preview listener fd `{raw_fd}`"),
        ));
    }
    // SAFETY: inner sandbox setup is single-threaded before the final command execs.
    unsafe {
        std::env::remove_var(SITES_PREVIEW_LISTENER_FD_ENV_VAR);
    }
    Ok(Some(listener_fd))
}

pub(crate) fn activate_sites_preview(listener_fd: libc::c_int) -> io::Result<()> {
    crate::proxy_routing::ensure_loopback_interface_up()?;
    // SAFETY: Sites preview activation runs before the sandboxed command starts threads.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let error = io::Error::last_os_error();
        close_fd(listener_fd)?;
        return Err(error);
    }

    if pid == 0 {
        if crate::proxy_routing::harden_bridge_process()
            .and_then(|()| run_sites_preview_bridge(listener_fd))
            .is_err()
        {
            // SAFETY: this is the forked bridge child; `_exit` avoids unwinding through fork.
            unsafe { libc::_exit(1) };
        }
        // SAFETY: this is the forked bridge child after its bridge loop returns.
        unsafe { libc::_exit(0) };
    }

    close_fd(listener_fd)
}

fn run_sites_preview_bridge(listener_fd: libc::c_int) -> io::Result<()> {
    // SAFETY: exec-server transferred ownership of this inherited listener to the bridge child.
    let listener = unsafe { TcpListener::from_raw_fd(listener_fd) };
    let connection_limiter = Arc::new(ConnectionLimiter::new(MAX_CONCURRENT_CONNECTIONS));
    loop {
        let connection_permit = connection_limiter.acquire();
        let (browser_stream, _) = listener.accept()?;
        thread::spawn(move || {
            let _connection_permit = connection_permit;
            let site_stream = match connect_sites_preview_server_with_retry() {
                Ok(site_stream) => site_stream,
                Err(_) => return,
            };
            if set_connection_timeouts(&browser_stream)
                .and_then(|()| set_connection_timeouts(&site_stream))
                .is_err()
            {
                return;
            }
            let _ = proxy_bidirectional(browser_stream, site_stream);
        });
    }
}

fn connect_sites_preview_server_with_retry() -> io::Result<TcpStream> {
    let deadline = Instant::now() + LOCAL_SERVER_CONNECT_TIMEOUT;
    loop {
        match TcpStream::connect((Ipv4Addr::LOCALHOST, SITES_PREVIEW_PORT)) {
            Ok(stream) => return Ok(stream),
            Err(error) if Instant::now() < deadline => {
                thread::sleep(LOCAL_SERVER_CONNECT_RETRY_DELAY);
                let _ = error;
            }
            Err(error) => return Err(error),
        }
    }
}

fn proxy_bidirectional(
    mut browser_stream: TcpStream,
    mut site_stream: TcpStream,
) -> io::Result<()> {
    let mut browser_reader = browser_stream.try_clone()?;
    let mut site_writer = site_stream.try_clone()?;
    let browser_to_site =
        thread::spawn(move || std::io::copy(&mut browser_reader, &mut site_writer));
    let site_to_browser = std::io::copy(&mut site_stream, &mut browser_stream);
    let browser_to_site = browser_to_site
        .join()
        .map_err(|_| io::Error::other("Sites preview bridge thread panicked"))?;
    browser_to_site?;
    site_to_browser?;
    Ok(())
}

fn set_connection_timeouts(stream: &TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(CONNECTION_IDLE_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_IDLE_TIMEOUT))
}

struct ConnectionLimiter {
    max_connections: usize,
    active_connections: Mutex<usize>,
    connection_available: Condvar,
}

impl ConnectionLimiter {
    fn new(max_connections: usize) -> Self {
        Self {
            max_connections,
            active_connections: Mutex::new(0),
            connection_available: Condvar::new(),
        }
    }

    fn acquire(self: &Arc<Self>) -> ConnectionPermit {
        let mut active_connections = self
            .active_connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *active_connections >= self.max_connections {
            active_connections = self
                .connection_available
                .wait(active_connections)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        *active_connections += 1;
        ConnectionPermit {
            limiter: Arc::clone(self),
        }
    }
}

struct ConnectionPermit {
    limiter: Arc<ConnectionLimiter>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let mut active_connections = self
            .limiter
            .active_connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *active_connections -= 1;
        self.limiter.connection_available.notify_one();
    }
}

fn close_fd(fd: libc::c_int) -> io::Result<()> {
    // SAFETY: callers pass a live inherited file descriptor owned by this process.
    let result = unsafe { libc::close(fd) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn listener_fd_is_taken_from_env() {
        // SAFETY: this test mutates the process environment before spawning threads.
        unsafe {
            std::env::set_var(SITES_PREVIEW_LISTENER_FD_ENV_VAR, "17");
        }

        assert_eq!(
            take_sites_preview_listener_fd_from_env().expect("take listener fd"),
            Some(17)
        );
        assert_eq!(
            std::env::var(SITES_PREVIEW_LISTENER_FD_ENV_VAR),
            Err(std::env::VarError::NotPresent)
        );
    }

    #[test]
    fn connection_limiter_waits_for_available_slot() {
        let connection_limiter = Arc::new(ConnectionLimiter::new(1));
        let first_connection = connection_limiter.acquire();
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let waiting_limiter = Arc::clone(&connection_limiter);
        let waiting_connection = thread::spawn(move || {
            let _second_connection = waiting_limiter.acquire();
            acquired_tx.send(()).expect("report acquired connection");
        });

        assert!(
            acquired_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "second connection should wait for the first connection to close"
        );
        drop(first_connection);
        acquired_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("second connection should acquire released slot");
        waiting_connection.join().expect("join waiting connection");
    }
}
