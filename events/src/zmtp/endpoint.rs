//! Endpoint parsing and binding for the ZMTP PUB server.
//!
//! Supported forms, with libzmq's meaning:
//! - `tcp://<ipv4>:<port>` and `tcp://[<ipv6>]:<port>`;
//! - `tcp://*:<port>`, every IPv4 interface (`0.0.0.0`), which is what
//!   libzmq binds for `*` when the socket is not in IPv6 mode;
//! - `tcp://<hostname>:<port>`, resolved once at bind. The first IPv4
//!   result is preferred, as libzmq resolves only IPv4 for a socket not in
//!   IPv6 mode; an IPv6-only name falls back to its first result;
//! - port `0` or `*` binds an ephemeral port;
//! - `ipc://<path>`, a Unix-domain socket.
//!
//! Not supported: interface names (`tcp://eth0:5555`), wildcard
//! (`ipc://*`) and abstract (`ipc://@name`) ipc paths, and every other
//! transport. They fail the bind with a message naming the form.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use tokio::net::{TcpListener, UnixListener};

pub(crate) enum Listener {
    Tcp(TcpListener),
    Ipc(UnixListener),
}

/// A bound listener, the endpoint it resolved to, and for `ipc://` the
/// file to remove when the socket closes.
pub(crate) struct Bound {
    pub listener: Listener,
    pub local_endpoint: String,
    pub ipc_file: Option<IpcFile>,
}

pub(crate) async fn bind(endpoint: &str) -> io::Result<Bound> {
    if let Some(rest) = endpoint.strip_prefix("tcp://") {
        let addr = resolve_tcp(rest).await?;
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        Ok(Bound {
            listener: Listener::Tcp(listener),
            local_endpoint: format!("tcp://{local}"),
            ipc_file: None,
        })
    } else if let Some(path) = endpoint.strip_prefix("ipc://") {
        let (listener, file) = bind_ipc(path)?;
        Ok(Bound {
            listener: Listener::Ipc(listener),
            local_endpoint: format!("ipc://{path}"),
            ipc_file: Some(file),
        })
    } else {
        Err(invalid(format!(
            "unsupported endpoint {endpoint:?}: only tcp:// and ipc:// are supported"
        )))
    }
}

async fn resolve_tcp(rest: &str) -> io::Result<SocketAddr> {
    let Some((host, port)) = rest.rsplit_once(':') else {
        return Err(invalid(format!("tcp endpoint {rest:?} has no port")));
    };
    let port: u16 = match port {
        "*" => 0,
        p => p
            .parse()
            .map_err(|_| invalid(format!("tcp endpoint {rest:?} has an invalid port")))?,
    };
    if host == "*" {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
    }
    if let Some(v6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        let ip: IpAddr = v6
            .parse()
            .map_err(|_| invalid(format!("tcp endpoint {rest:?} has an invalid IPv6 address")))?;
        return Ok(SocketAddr::new(ip, port));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    if host.is_empty() {
        return Err(invalid(format!("tcp endpoint {rest:?} has no host")));
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| invalid(format!("{host:?} did not resolve to any address")))
}

/// Bind a Unix-domain listener at `path`.
///
/// A file already at the path is removed first only when it is a socket:
/// the usual leftover of a previous run that did not clean up. libzmq
/// (v4.3.5 `src/ipc_listener.cpp`, `ipc_listener_t::set_local_address`)
/// unlinks whatever is there, of any type; this refuses instead when the
/// path holds anything else, so a mistyped path cannot delete an
/// operator's file.
fn bind_ipc(path: &str) -> io::Result<(UnixListener, IpcFile)> {
    if path.is_empty() {
        return Err(invalid("ipc endpoint has no path"));
    }
    if path == "*" || path.starts_with('@') {
        return Err(invalid(format!(
            "ipc endpoint {path:?}: wildcard and abstract ipc paths are not supported"
        )));
    }
    let p = Path::new(path);
    match std::fs::symlink_metadata(p) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(p)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{path} exists and is not a socket; refusing to replace it"),
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(p)?;
    let meta = std::fs::symlink_metadata(p)?;
    Ok((
        listener,
        IpcFile {
            path: p.to_path_buf(),
            dev: meta.dev(),
            ino: meta.ino(),
        },
    ))
}

/// The socket file an `ipc://` bind created. Dropping it removes the file,
/// but only while the path still names the socket this bind created:
/// another process that has since bound the same path keeps its file.
pub(crate) struct IpcFile {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl Drop for IpcFile {
    fn drop(&mut self) {
        if let Ok(meta) = std::fs::symlink_metadata(&self.path)
            && meta.file_type().is_socket()
            && meta.dev() == self.dev
            && meta.ino() == self.ino
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}
