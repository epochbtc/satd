use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Client for the Tor control port protocol.
///
/// Implements the subset needed for hidden service management:
/// - AUTHENTICATE (password or empty)
/// - ADD_ONION (create ephemeral hidden service)
/// - DEL_ONION (remove hidden service on shutdown)
pub struct TorController {
    reader: BufReader<tokio::io::ReadHalf<TcpStream>>,
    writer: tokio::io::WriteHalf<TcpStream>,
}

impl TorController {
    /// Connect to the Tor control port.
    pub async fn connect(addr: &str) -> Result<Self, String> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("Tor control connect to {} failed: {}", addr, e))?;

        let (read_half, write_half) = tokio::io::split(stream);
        Ok(Self {
            reader: BufReader::new(read_half),
            writer: write_half,
        })
    }

    /// Authenticate with the Tor control port.
    /// An empty password uses cookie authentication (Tor default).
    pub async fn authenticate(&mut self, password: &str) -> Result<(), String> {
        let cmd = if password.is_empty() {
            "AUTHENTICATE\r\n".to_string()
        } else {
            format!("AUTHENTICATE \"{}\"\r\n", password)
        };

        self.writer
            .write_all(cmd.as_bytes())
            .await
            .map_err(|e| format!("Tor auth write failed: {}", e))?;

        let response = self.read_response().await?;
        if !response.starts_with("250") {
            return Err(format!("Tor AUTHENTICATE failed: {}", response));
        }
        Ok(())
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

    /// Read a single line response from the control port.
    async fn read_response(&mut self) -> Result<String, String> {
        let mut line = String::new();
        self.reader
            .read_line(&mut line)
            .await
            .map_err(|e| format!("Tor control read failed: {}", e))?;
        Ok(line.trim_end().to_string())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_strip_onion_suffix() {
        let host = "abc123def456.onion";
        let id = host.strip_suffix(".onion").unwrap();
        assert_eq!(id, "abc123def456");
    }
}
