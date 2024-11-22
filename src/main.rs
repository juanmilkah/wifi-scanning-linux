use std::process::Command;

#[derive(Debug)]
struct WifiNetwork {
    ssid: String,
    signal_strength: i32,
    security: String,
}

fn scan_networks() -> Vec<WifiNetwork> {
    let mut networks = Vec::new();

    // Try using iwlist for scanning
    if let Ok(output) = Command::new("sudo").args(["iwlist", "scanning"]).output() {
        let output = String::from_utf8_lossy(&output.stdout);
        let mut current_network = None;
        let mut signal_strength = 0;
        let mut security = String::new();

        for line in output.lines() {
            let line = line.trim();

            if line.starts_with("Cell") {
                // Save previous network if exists
                if let Some(ssid) = current_network {
                    networks.push(WifiNetwork {
                        ssid,
                        signal_strength,
                        security: security.clone(),
                    });
                }
                current_network = None;
                security.clear();
            } else if line.starts_with("ESSID:") {
                let ssid = line[7..].trim_matches('"').to_string();
                current_network = Some(ssid);
            } else if line.contains("Signal level=") {
                if let Some(idx) = line.find("Signal level=") {
                    if let Ok(level) = line[idx + 13..]
                        .split_whitespace()
                        .next()
                        .unwrap_or("-0")
                        .replace("/", "")
                        .parse::<i32>()
                    {
                        signal_strength = level;
                    }
                }
            } else if line.contains("Encryption key:") {
                security = if line.contains("on") {
                    "Secured".to_string()
                } else {
                    "Open".to_string()
                };
            }
        }

        // Add last network
        if let Some(ssid) = current_network {
            networks.push(WifiNetwork {
                ssid,
                signal_strength,
                security,
            });
        }
    }

    networks
}

fn main() {
    println!("Scanning for WiFi networks...");

    let networks = scan_networks();

    if networks.is_empty() {
        println!("Note: On Linux, this program needs sudo privileges.");
        return;
    }

    println!("\nFound {} networks:", networks.len());
    println!("{:<30} {:<15} Security", "SSID", "Signal Strength");
    println!("{:-<60}", "");

    for network in networks {
        println!(
            "{:<30} {:<15} {}",
            network.ssid, network.signal_strength, network.security
        );
    }
}
