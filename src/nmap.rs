use std::path::Path;

use quick_xml::events::Event;
use quick_xml::Reader;

#[derive(Debug, Clone)]
pub struct NmapPort {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: String,
}

#[derive(Debug, Clone)]
pub struct NmapHost {
    pub addr: String,
    pub ports: Vec<NmapPort>,
}

#[derive(Debug, Clone, Default)]
pub struct NmapScan {
    pub hosts: Vec<NmapHost>,
}

fn extract_attr(e: &quick_xml::events::BytesStart, key: &[u8]) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| a.key.as_ref() == key)
        .map(|a| String::from_utf8_lossy(&a.value).to_string())
}

impl NmapScan {
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read nmap file {}: {e}", path.display()))?;
        Self::parse(&content)
    }

    pub fn parse(xml: &str) -> Result<Self, String> {
        let mut reader = Reader::from_str(xml);
        let mut scan = NmapScan::default();
        let mut buf = Vec::new();
        let mut current_host: Option<NmapHost> = None;
        let mut current_port: Option<NmapPort> = None;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    match tag.as_str() {
                        "host" => {
                            current_host = Some(NmapHost {
                                addr: String::new(),
                                ports: vec![],
                            });
                        }
                        "address" => {
                            if let Some(ref mut host) = current_host {
                                if let Some(addr) = extract_attr(&e, b"addr") {
                                    host.addr = addr;
                                }
                            }
                        }
                        "port" => {
                            let port_id: u16 = extract_attr(&e, b"portid")
                                .and_then(|v| v.parse().ok())
                                .unwrap_or(0);
                            let proto = extract_attr(&e, b"protocol").unwrap_or_default();
                            current_port = Some(NmapPort {
                                port: port_id,
                                protocol: proto,
                                state: String::new(),
                                service: String::new(),
                            });
                        }
                        "state" => {
                            if let Some(ref mut p) = current_port {
                                p.state = extract_attr(&e, b"state").unwrap_or_default();
                            }
                        }
                        "service" => {
                            if let Some(ref mut p) = current_port {
                                p.service = extract_attr(&e, b"name").unwrap_or_default();
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    match tag.as_str() {
                        "port" => {
                            if let (Some(ref mut host), Some(port)) =
                                (&mut current_host, current_port.take())
                            {
                                host.ports.push(port);
                            }
                        }
                        "host" => {
                            if let Some(host) = current_host.take() {
                                scan.hosts.push(host);
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(format!("nmap XML parse error: {e}")),
                _ => {}
            }
            buf.clear();
        }

        Ok(scan)
    }

    /// Extract unique TCP ports from all hosts that are in "open" state
    pub fn open_tcp_ports(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = self
            .hosts
            .iter()
            .flat_map(|h| &h.ports)
            .filter(|p| p.protocol == "tcp" && p.state == "open")
            .map(|p| p.port)
            .collect();
        ports.sort();
        ports.dedup();
        ports
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_NMAP: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addr-type="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="reset"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>"#;

    #[test]
    fn parse_nmap_xml() {
        let scan = NmapScan::parse(SAMPLE_NMAP).unwrap();
        assert_eq!(scan.hosts.len(), 1);
        assert_eq!(scan.hosts[0].addr, "192.168.1.1");
        assert_eq!(scan.hosts[0].ports.len(), 3);
    }

    #[test]
    fn extract_open_tcp_ports() {
        let scan = NmapScan::parse(SAMPLE_NMAP).unwrap();
        let ports = scan.open_tcp_ports();
        assert_eq!(ports, vec![22, 80]);
    }

    #[test]
    fn parse_multi_host() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addr-type="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="10.0.0.2" addr-type="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
      <port protocol="udp" portid="53">
        <state state="open"/>
        <service name="dns"/>
      </port>
    </ports>
  </host>
</nmaprun>"#;
        let scan = NmapScan::parse(xml).unwrap();
        assert_eq!(scan.hosts.len(), 2);
        let ports = scan.open_tcp_ports();
        assert_eq!(ports, vec![22, 80]);
    }
}
