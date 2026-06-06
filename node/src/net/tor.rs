use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

type HmacSha256 = Hmac<Sha256>;

/// HMAC key Tor uses for the SAFECOOKIE server proof (control-spec §3.24).
const SERVER_HASH_KEY: &[u8] = b"Tor safe cookie authentication server-to-controller hash";
/// HMAC key Tor uses for the SAFECOOKIE client proof.
const CLIENT_HASH_KEY: &[u8] = b"Tor safe cookie authentication controller-to-server hash";
/// The control-port authentication cookie is exactly 32 bytes.
const COOKIE_LEN: usize = 32;
/// Bound for a single control-port connect/read. Hidden-service bring-up runs on
/// the startup path, so a hung or half-open control port (a wedged Tor, or a
/// non-Tor process squatting the port that accepts then never replies) must not
/// stall satd forever. Generous for a busy local Tor, short enough to fail.
const CONTROL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// Cap on lines in a single control reply (anti-flood): a real
/// PROTOCOLINFO/AUTHCHALLENGE reply is a handful of lines, so a port streaming
/// continuation lines without a terminator is refused rather than read forever.
const MAX_REPLY_LINES: usize = 256;

/// Auth methods a Tor control port may advertise via `PROTOCOLINFO`.
#[derive(Debug, Default, Clone)]
struct AuthMethods {
    null: bool,
    hashedpassword: bool,
    safecookie: bool,
    cookie_file: Option<String>,
}

/// Client for the Tor control port protocol.
///
/// Implements the subset needed for hidden service management:
/// - PROTOCOLINFO (discover auth methods + cookie file)
/// - AUTHENTICATE — SAFECOOKIE (default), password (`-torpassword`), or null
/// - ADD_ONION (create ephemeral hidden service)
/// - DEL_ONION (remove hidden service on shutdown)
///
/// An `ADD_ONION` ephemeral service is removed by Tor when the **originating
/// control connection closes** (no `Detach` flag), so the caller must keep this
/// controller alive for as long as the hidden service should exist. Dropping it
/// (e.g. at process exit) is itself a clean teardown.
pub struct TorController {
    reader: BufReader<tokio::io::ReadHalf<TcpStream>>,
    writer: tokio::io::WriteHalf<TcpStream>,
}

impl TorController {
    /// Connect to the Tor control port.
    pub async fn connect(addr: &str) -> Result<Self, String> {
        let stream = tokio::time::timeout(CONTROL_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| format!("Tor control connect to {} timed out", addr))?
            .map_err(|e| format!("Tor control connect to {} failed: {}", addr, e))?;

        let (read_half, write_half) = tokio::io::split(stream);
        Ok(Self {
            reader: BufReader::new(read_half),
            writer: write_half,
        })
    }

    /// Authenticate with the Tor control port.
    ///
    /// Negotiates the method from `PROTOCOLINFO`, preferring (in order):
    /// 1. password, when one is supplied and the port offers `HASHEDPASSWORD`;
    /// 2. **SAFECOOKIE**, when offered and the cookie file is readable — this is
    ///    the stock-Tor default (`CookieAuthentication 1`), so it works without
    ///    an operator-configured `HashedControlPassword`;
    /// 3. null auth, when the port requires no credentials;
    /// 4. password as a last resort, if supplied.
    ///
    /// SAFECOOKIE (control-spec §3.24) proves cookie knowledge without sending
    /// the cookie, and verifies the server's proof too, so a rogue process
    /// squatting the control port can't trick us into authenticating.
    pub async fn authenticate(&mut self, password: Option<&str>) -> Result<(), String> {
        let methods = self.protocol_info().await?;

        if let Some(pw) = password.filter(|p| !p.is_empty())
            && methods.hashedpassword
        {
            return self.authenticate_password(pw).await;
        }
        if methods.safecookie {
            match &methods.cookie_file {
                Some(path) => return self.authenticate_safecookie(path).await,
                None => {
                    return Err(
                        "Tor offers SAFECOOKIE but PROTOCOLINFO gave no COOKIEFILE".to_string(),
                    );
                }
            }
        }
        if methods.null {
            return self.authenticate_null().await;
        }
        if let Some(pw) = password.filter(|p| !p.is_empty()) {
            return self.authenticate_password(pw).await;
        }
        Err(
            "Tor control port requires authentication satd can't satisfy: SAFECOOKIE not offered \
             (or its cookie is unreadable) and no -torpassword set. Set -torpassword to match the \
             control port's HashedControlPassword, or make the cookie file group-readable \
             (CookieAuthFileGroupReadable 1)."
                .to_string(),
        )
    }

    /// Query `PROTOCOLINFO` for the supported auth methods and cookie path.
    async fn protocol_info(&mut self) -> Result<AuthMethods, String> {
        self.writer
            .write_all(b"PROTOCOLINFO 1\r\n")
            .await
            .map_err(|e| format!("Tor PROTOCOLINFO write failed: {}", e))?;

        let mut methods = AuthMethods::default();
        for line in self.read_reply().await? {
            // 250-AUTH METHODS=NULL,SAFECOOKIE COOKIEFILE="/run/tor/control.authcookie"
            if let Some(rest) = line
                .strip_prefix("250-AUTH ")
                .or_else(|| line.strip_prefix("250 AUTH "))
            {
                if let Some(list) = token_value(rest, "METHODS=") {
                    for m in list.split(',') {
                        match m.trim() {
                            "NULL" => methods.null = true,
                            "HASHEDPASSWORD" => methods.hashedpassword = true,
                            "SAFECOOKIE" => methods.safecookie = true,
                            _ => {}
                        }
                    }
                }
                if let Some(file) = token_value(rest, "COOKIEFILE=") {
                    methods.cookie_file = Some(unquote(file));
                }
            }
        }
        Ok(methods)
    }

    /// SAFECOOKIE challenge/response (control-spec §3.24).
    async fn authenticate_safecookie(&mut self, cookie_path: &str) -> Result<(), String> {
        // `cookie_path` comes from the control port's own PROTOCOLINFO response,
        // so a hostile/compromised control port could point it at any 32-byte
        // file satd can read. That is acceptable under the standard "the local
        // control port is trusted" model (same as Bitcoin Core): the bytes are
        // only fed into the HMAC, never sent or logged, and the SERVERHASH check
        // below fails unless the port already knows the file — i.e. it is the
        // real Tor. No confidentiality leak results.
        let cookie = std::fs::read(cookie_path).map_err(|e| {
            format!(
                "Tor SAFECOOKIE: cannot read cookie file {}: {} (run satd as a user that can read \
                 it, or set CookieAuthFileGroupReadable 1 in torrc)",
                cookie_path, e
            )
        })?;
        if cookie.len() != COOKIE_LEN {
            return Err(format!(
                "Tor SAFECOOKIE: cookie file {} is {} bytes, expected {}",
                cookie_path,
                cookie.len(),
                COOKIE_LEN
            ));
        }

        let client_nonce: [u8; 32] = rand::random();
        self.writer
            .write_all(
                format!("AUTHCHALLENGE SAFECOOKIE {}\r\n", hex::encode(client_nonce)).as_bytes(),
            )
            .await
            .map_err(|e| format!("Tor AUTHCHALLENGE write failed: {}", e))?;

        // 250 AUTHCHALLENGE SERVERHASH=<hex> SERVERNONCE=<hex>
        let reply = self.read_reply().await?;
        let line = reply
            .iter()
            .find(|l| l.contains("AUTHCHALLENGE"))
            .ok_or_else(|| format!("Tor AUTHCHALLENGE failed: {}", reply.join(" / ")))?;
        let server_hash = token_value(line, "SERVERHASH=")
            .and_then(|h| hex::decode(h).ok())
            .ok_or("Tor AUTHCHALLENGE: missing/!hex SERVERHASH")?;
        let server_nonce_hex =
            token_value(line, "SERVERNONCE=").ok_or("Tor AUTHCHALLENGE: missing SERVERNONCE")?;
        let server_nonce =
            hex::decode(server_nonce_hex).map_err(|_| "Tor AUTHCHALLENGE: !hex SERVERNONCE")?;

        // msg = cookie || client_nonce || server_nonce
        let mut msg = Vec::with_capacity(cookie.len() + 32 + server_nonce.len());
        msg.extend_from_slice(&cookie);
        msg.extend_from_slice(&client_nonce);
        msg.extend_from_slice(&server_nonce);

        // Verify the server actually knows the cookie before we send our proof —
        // otherwise a process squatting the control port could elicit a hash.
        let expected_server = hmac(SERVER_HASH_KEY, &msg);
        if ct_ne(&expected_server, &server_hash) {
            return Err(
                "Tor SAFECOOKIE: SERVERHASH mismatch — the control port did not prove cookie \
                 knowledge (possible wrong cookie file or a rogue listener)"
                    .to_string(),
            );
        }

        let client_hash = hmac(CLIENT_HASH_KEY, &msg);
        self.writer
            .write_all(format!("AUTHENTICATE {}\r\n", hex::encode(client_hash)).as_bytes())
            .await
            .map_err(|e| format!("Tor AUTHENTICATE write failed: {}", e))?;
        self.expect_250("AUTHENTICATE (SAFECOOKIE)").await
    }

    async fn authenticate_password(&mut self, password: &str) -> Result<(), String> {
        // The control protocol is line-oriented; a CR/LF in the password would
        // terminate the AUTHENTICATE line early and inject a second command.
        // Reject rather than escape — a newline in a control password is always
        // a misconfiguration.
        if password.contains(['\r', '\n']) {
            return Err("Tor control password must not contain CR or LF".to_string());
        }
        // Control-spec quoting: backslash-escape `\` and `"`.
        let escaped = password.replace('\\', "\\\\").replace('"', "\\\"");
        self.writer
            .write_all(format!("AUTHENTICATE \"{}\"\r\n", escaped).as_bytes())
            .await
            .map_err(|e| format!("Tor auth write failed: {}", e))?;
        self.expect_250("AUTHENTICATE (password)").await
    }

    async fn authenticate_null(&mut self) -> Result<(), String> {
        self.writer
            .write_all(b"AUTHENTICATE\r\n")
            .await
            .map_err(|e| format!("Tor auth write failed: {}", e))?;
        self.expect_250("AUTHENTICATE (null)").await
    }

    /// Create an ephemeral hidden service.
    /// Returns the .onion hostname (without the .onion suffix — caller appends it).
    ///
    /// Uses ADD_ONION with NEW:ED25519-V3 to create a v3 onion service.
    /// The service maps `virtual_port` on the .onion address to `target_addr` locally.
    pub async fn create_hidden_service(
        &mut self,
        virtual_port: u16,
        target_addr: &str,
    ) -> Result<String, String> {
        let cmd = format!(
            "ADD_ONION NEW:ED25519-V3 Port={},{} Flags=DiscardPK\r\n",
            virtual_port, target_addr
        );

        self.writer
            .write_all(cmd.as_bytes())
            .await
            .map_err(|e| format!("Tor ADD_ONION write failed: {}", e))?;

        // Response format:
        // 250-ServiceID=<base32-hostname>
        // 250 OK
        let mut service_id = None;
        loop {
            let line = self.read_response().await?;
            if let Some(id) = line.strip_prefix("250-ServiceID=") {
                service_id = Some(id.trim().to_string());
            } else if line.starts_with("250 ") {
                break;
            } else if line.starts_with("5") {
                return Err(format!("Tor ADD_ONION failed: {}", line));
            }
        }

        let id = service_id.ok_or("Tor ADD_ONION: no ServiceID in response")?;
        Ok(format!("{}.onion", id))
    }

    /// Remove a previously created hidden service.
    pub async fn remove_hidden_service(&mut self, onion_host: &str) -> Result<(), String> {
        // Strip .onion suffix for the DEL_ONION command
        let service_id = onion_host
            .strip_suffix(".onion")
            .unwrap_or(onion_host);

        let cmd = format!("DEL_ONION {}\r\n", service_id);

        self.writer
            .write_all(cmd.as_bytes())
            .await
            .map_err(|e| format!("Tor DEL_ONION write failed: {}", e))?;

        let response = self.read_response().await?;
        if !response.starts_with("250") {
            return Err(format!("Tor DEL_ONION failed: {}", response));
        }
        Ok(())
    }

    /// Read a single line response from the control port, bounded by
    /// [`CONTROL_TIMEOUT`] so a silent/half-open port can't block forever (the
    /// timeout also caps an unterminated slowloris dribble of bytes).
    async fn read_response(&mut self) -> Result<String, String> {
        let mut line = String::new();
        let n = tokio::time::timeout(CONTROL_TIMEOUT, self.reader.read_line(&mut line))
            .await
            .map_err(|_| "Tor control read timed out".to_string())?
            .map_err(|e| format!("Tor control read failed: {}", e))?;
        if n == 0 {
            return Err("Tor control port closed the connection".to_string());
        }
        Ok(line.trim_end().to_string())
    }

    /// Read a full control reply: continuation lines (`250-`/`250+`) until the
    /// terminating `250 ` (space) line. Returns every line, terminator included.
    /// An error status (`4xx`/`5xx`) returns the lines as an `Err`.
    async fn read_reply(&mut self) -> Result<Vec<String>, String> {
        let mut lines = Vec::new();
        // Count every read, including skipped async-event lines, so a port that
        // streams `6xx` events forever still hits the cap rather than looping.
        let mut reads = 0usize;
        loop {
            if reads >= MAX_REPLY_LINES {
                return Err("Tor control reply exceeded line cap".to_string());
            }
            reads += 1;
            let line = self.read_response().await?;
            // Async event lines (`6xx`) can arrive unsolicited on the control
            // connection; they are not part of a command reply, so skip them
            // rather than mistaking one for this reply's terminal line.
            if line.starts_with('6') {
                continue;
            }
            let terminal = line.len() >= 4 && line.as_bytes()[3] == b' ';
            let is_ok = line.starts_with('2');
            lines.push(line);
            if terminal {
                if !is_ok {
                    return Err(lines.join(" / "));
                }
                break;
            }
        }
        Ok(lines)
    }

    /// Read one reply and require a 250 status.
    async fn expect_250(&mut self, what: &str) -> Result<(), String> {
        let reply = self.read_reply().await?;
        let ok = reply.last().map(|l| l.starts_with("250")).unwrap_or(false);
        if ok {
            Ok(())
        } else {
            Err(format!("Tor {} failed: {}", what, reply.join(" / ")))
        }
    }
}

/// HMAC-SHA256(key, msg).
fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// Length-independent byte comparison: returns true when the slices differ,
/// without short-circuiting on the first differing byte of the server hash.
fn ct_ne(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return true;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff != 0
}

/// Extract the value following `key` in a space-separated control line, up to
/// the next space (e.g. `token_value("METHODS=A,B COOKIEFILE=\"x\"", "METHODS=")`
/// → `Some("A,B")`). Quoted values keep their quotes; use [`unquote`].
///
/// `key` is matched only at a **token boundary** (start of line or right after a
/// space), so a value can't smuggle a decoy `KEY=` as a substring of another
/// token. `match_indices` yields matches at char boundaries, so the slicing
/// below can't panic on a non-ASCII line.
fn token_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let start = line
        .match_indices(key)
        .find(|(idx, _)| *idx == 0 || line.as_bytes()[idx - 1] == b' ')
        .map(|(idx, _)| idx + key.len())?;
    let rest = &line[start..];
    // A quoted value may contain spaces; take through the closing quote.
    if let Some(after_quote) = rest.strip_prefix('"') {
        let end = after_quote.find('"').map(|i| i + 2).unwrap_or(rest.len());
        Some(&rest[..end])
    } else {
        let end = rest.find(' ').unwrap_or(rest.len());
        Some(&rest[..end])
    }
}

/// Strip surrounding quotes and unescape `\\`/`\"` from a control-protocol string.
fn unquote(s: &str) -> String {
    let inner = s
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s);
    inner.replace("\\\"", "\"").replace("\\\\", "\\")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn test_strip_onion_suffix() {
        let host = "abc123def456.onion";
        let id = host.strip_suffix(".onion").unwrap();
        assert_eq!(id, "abc123def456");
    }

    #[test]
    fn token_value_parses_methods_and_cookiefile() {
        let line = r#"250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE="/run/tor/control.authcookie""#;
        assert_eq!(token_value(line, "METHODS="), Some("COOKIE,SAFECOOKIE"));
        assert_eq!(
            unquote(token_value(line, "COOKIEFILE=").unwrap()),
            "/run/tor/control.authcookie"
        );
    }

    #[test]
    fn token_value_handles_quoted_path_with_space() {
        let line = r#"250-AUTH METHODS=SAFECOOKIE COOKIEFILE="/var/lib/tor data/control.authcookie""#;
        assert_eq!(
            unquote(token_value(line, "COOKIEFILE=").unwrap()),
            "/var/lib/tor data/control.authcookie"
        );
    }

    #[test]
    fn token_value_is_token_anchored_not_substring() {
        // `SERVERHASH=` must match the real token, not the `SERVERHASH=` substring
        // inside a decoy token like `NOTSERVERHASH=`.
        let line = "250 AUTHCHALLENGE NOTSERVERHASH=dead SERVERHASH=beef SERVERNONCE=cafe";
        assert_eq!(token_value(line, "SERVERHASH="), Some("beef"));
        assert_eq!(token_value(line, "SERVERNONCE="), Some("cafe"));
    }

    /// A minimal Tor control port that drives the real SAFECOOKIE handshake
    /// against `TorController`, computing the server proof the way Tor does.
    /// Returns the client proof it received (empty if the client hung up).
    async fn fake_tor_safecookie(
        listener: TcpListener,
        cookie: [u8; 32],
        cookie_path: std::path::PathBuf,
        corrupt_server_hash: bool,
    ) -> Result<Vec<u8>, String> {
        std::fs::write(&cookie_path, cookie).map_err(|e| e.to_string())?;
        let (stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let (rh, mut wh) = tokio::io::split(stream);
        let mut reader = BufReader::new(rh);

        // PROTOCOLINFO
        let mut l = String::new();
        reader.read_line(&mut l).await.map_err(|e| e.to_string())?;
        assert!(l.starts_with("PROTOCOLINFO"), "got: {l}");
        wh.write_all(
            format!(
                "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=SAFECOOKIE COOKIEFILE=\"{}\"\r\n250 OK\r\n",
                cookie_path.display()
            )
            .as_bytes(),
        )
        .await
        .map_err(|e| e.to_string())?;

        // AUTHCHALLENGE SAFECOOKIE <client_nonce>
        let mut chal = String::new();
        reader.read_line(&mut chal).await.map_err(|e| e.to_string())?;
        let chal = chal.trim_end();
        let client_nonce_hex = chal
            .strip_prefix("AUTHCHALLENGE SAFECOOKIE ")
            .ok_or_else(|| format!("bad AUTHCHALLENGE: {chal}"))?;
        let client_nonce = hex::decode(client_nonce_hex).map_err(|e| e.to_string())?;
        let server_nonce: [u8; 32] = rand::random();

        let mut msg = Vec::new();
        msg.extend_from_slice(&cookie);
        msg.extend_from_slice(&client_nonce);
        msg.extend_from_slice(&server_nonce);
        let mut server_hash = hmac(SERVER_HASH_KEY, &msg);
        if corrupt_server_hash {
            server_hash[0] ^= 0xff;
        }
        wh.write_all(
            format!(
                "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                hex::encode(&server_hash),
                hex::encode(server_nonce)
            )
            .as_bytes(),
        )
        .await
        .map_err(|e| e.to_string())?;

        // AUTHENTICATE <client_hash>  (only sent if the client accepted us)
        let mut auth = String::new();
        let n = reader.read_line(&mut auth).await.map_err(|e| e.to_string())?;
        let _ = std::fs::remove_file(&cookie_path);
        if n == 0 {
            return Ok(Vec::new()); // client hung up (rejected our SERVERHASH)
        }
        let auth = auth.trim_end();
        let client_hash_hex = auth
            .strip_prefix("AUTHENTICATE ")
            .ok_or_else(|| format!("bad AUTHENTICATE: {auth}"))?;
        let got = hex::decode(client_hash_hex).map_err(|e| e.to_string())?;
        let expected = hmac(CLIENT_HASH_KEY, &msg);
        if got == expected {
            wh.write_all(b"250 OK\r\n").await.map_err(|e| e.to_string())?;
        } else {
            wh.write_all(b"515 Bad authentication\r\n")
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(got)
    }

    fn unique_cookie_path(tag: &str) -> std::path::PathBuf {
        let nonce: u64 = rand::random();
        std::env::temp_dir().join(format!("satd-test-cookie-{}-{:016x}", tag, nonce))
    }

    #[tokio::test]
    async fn safecookie_handshake_succeeds_against_fake_tor() {
        let cookie: [u8; 32] = rand::random();
        let path = unique_cookie_path("ok");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(fake_tor_safecookie(listener, cookie, path, false));

        let mut ctrl = TorController::connect(&addr).await.unwrap();
        ctrl.authenticate(None)
            .await
            .expect("SAFECOOKIE auth should succeed");

        let client_hash = tokio::time::timeout(std::time::Duration::from_secs(30), server)
            .await
            .expect("fake-tor server task timed out")
            .unwrap()
            .unwrap();
        assert_eq!(client_hash.len(), 32, "server received a 32-byte client proof");
    }

    #[tokio::test]
    async fn safecookie_rejects_bad_server_hash() {
        // A control port that can't prove cookie knowledge must be refused before
        // we disclose our own proof (MITM / rogue-listener protection).
        let cookie: [u8; 32] = rand::random();
        let path = unique_cookie_path("bad");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(fake_tor_safecookie(listener, cookie, path, true));

        let mut ctrl = TorController::connect(&addr).await.unwrap();
        let err = ctrl.authenticate(None).await.unwrap_err();
        assert!(err.contains("SERVERHASH mismatch"), "got: {err}");

        // Drop the controller so the connection closes — this is what satd does
        // on an auth failure, and it lets the fake server's pending read see EOF
        // instead of blocking forever on an AUTHENTICATE that never comes.
        drop(ctrl);
        let sent = tokio::time::timeout(std::time::Duration::from_secs(30), server)
            .await
            .expect("fake-tor server task timed out")
            .unwrap()
            .unwrap();
        assert!(
            sent.is_empty(),
            "client leaked a proof to an unverified server"
        );
    }
}
