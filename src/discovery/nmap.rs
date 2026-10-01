use super::{DiscoveryBackend, DiscoveryError, DiscoveryRequest, DiscoveryResult};
use crate::nmap::NmapScan;
use std::process::Stdio;
use tokio::process::Command;

#[derive(Debug, Default, Clone, Copy)]
pub struct NmapBackend;

impl NmapBackend {
    async fn run(&self, request: &DiscoveryRequest, udp: bool) -> Result<NmapScan, DiscoveryError> {
        let mut command = Command::new("nmap");
        command
            .arg("-Pn")
            .arg("-oX")
            .arg("-")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if udp {
            command.arg("-sU");
            if let Some(ports) = &request.ports {
                command.arg("-p").arg(ports);
            } else {
                command.arg("--top-ports").arg("20");
            }
        } else {
            command.arg("-sT").arg("-sV").arg("--version-light");
            if let Some(ports) = &request.ports {
                command.arg("-p").arg(ports);
            } else {
                command.arg("-p-");
            }
        }

        let output = command
            .arg(&request.target)
            .output()
            .await
            .map_err(DiscoveryError::Io)?;
        if !output.status.success() {
            return Err(DiscoveryError::CommandFailed(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }

        NmapScan::parse(&String::from_utf8_lossy(&output.stdout)).map_err(DiscoveryError::Parse)
    }
}

impl DiscoveryBackend for NmapBackend {
    fn discover<'a>(
        &'a self,
        request: &'a DiscoveryRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<DiscoveryResult, DiscoveryError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let tcp = self.run(request, false).await?;
            let mut result = DiscoveryResult::from(tcp);

            // UDP scans usually require elevated privileges. Treat them as
            // best-effort so an unprivileged TCP discovery remains useful.
            if let Ok(udp) = self.run(request, true).await {
                let udp_result = DiscoveryResult::from(udp);
                for host in &mut result.hosts {
                    if let Some(udp_host) = udp_result
                        .hosts
                        .iter()
                        .find(|candidate| candidate.address == host.address)
                    {
                        host.services.extend(
                            udp_host
                                .services
                                .iter()
                                .filter(|service| service.protocol == super::Protocol::Udp)
                                .cloned(),
                        );
                    }
                }
            }

            Ok(result)
        })
    }
}
