use serde::Deserialize;
use anyhow::Result;
use crate::models;

// Raw XML deserialization structs (private -- not exposed outside parser)
#[derive(Debug, Deserialize)]
#[serde(rename = "nmaprun")]
struct NmapRun {
    #[serde(rename = "@args")]
    args: Option<String>,
    #[serde(rename = "@version")]
    version: Option<String>,
    #[serde(default)]
    host: Vec<XmlHost>,
}

#[derive(Debug, Deserialize)]
struct XmlHost {
    status: XmlStatus,
    #[serde(default)]
    address: Vec<XmlAddress>,
    hostnames: Option<XmlHostnames>,
    ports: Option<XmlPorts>,
}

#[derive(Debug, Deserialize)]
struct XmlStatus {
    #[serde(rename = "@state")]
    state: String,
}

#[derive(Debug, Deserialize)]
struct XmlAddress {
    #[serde(rename = "@addr")]
    addr: String,
    #[serde(rename = "@addrtype")]
    addrtype: Option<String>,
    #[serde(rename = "@vendor")]
    vendor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct XmlHostnames {
    #[serde(default)]
    hostname: Vec<XmlHostname>,
}

#[derive(Debug, Deserialize)]
struct XmlHostname {
    #[serde(rename = "@name")]
    name: Option<String>,
    #[serde(rename = "@type")]
    hostname_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct XmlPorts {
    #[serde(default)]
    port: Vec<XmlPort>,
}

#[derive(Debug, Deserialize)]
struct XmlPort {
    #[serde(rename = "@portid")]
    portid: u16,
    #[serde(rename = "@protocol")]
    protocol: String,
    state: Option<XmlPortState>,
    service: Option<XmlService>,
}

#[derive(Debug, Deserialize)]
struct XmlPortState {
    #[serde(rename = "@state")]
    state: String,
}

#[derive(Debug, Deserialize)]
struct XmlService {
    #[serde(rename = "@name")]
    name: String,
    #[serde(rename = "@product")]
    product: Option<String>,
    #[serde(rename = "@version")]
    version: Option<String>,
    #[serde(rename = "@extrainfo")]
    extrainfo: Option<String>,
    #[serde(rename = "@tunnel")]
    tunnel: Option<String>,
    #[serde(rename = "@hostname")]
    hostname: Option<String>,
    #[serde(rename = "@ostype")]
    ostype: Option<String>,
    #[serde(rename = "@devicetype")]
    devicetype: Option<String>,
    #[serde(rename = "@method")]
    method: Option<String>,
    #[serde(rename = "@conf")]
    conf: Option<String>,
    #[serde(default)]
    cpe: Vec<XmlCpe>,
}

#[derive(Debug, Deserialize)]
struct XmlCpe {
    #[serde(rename = "$text")]
    value: Option<String>,
}

/// Parse nmap XML output into a normalized ScanResult.
pub fn parse_xml(content: &str, source: &str) -> Result<models::ScanResult> {
    let nmap_run: NmapRun = quick_xml::de::from_str(content)?;

    let hosts = nmap_run
        .host
        .into_iter()
        .filter(|h| h.status.state == "up")
        .map(|xml_host| convert_host(xml_host))
        .collect();

    Ok(models::ScanResult {
        source: source.to_string(),
        hosts,
    })
}

fn convert_host(xml_host: XmlHost) -> models::Host {
    // Determine primary IP: prefer ipv4, fallback to first address
    let ip = xml_host
        .address
        .iter()
        .find(|a| a.addrtype.as_deref() == Some("ipv4"))
        .or_else(|| xml_host.address.first())
        .map(|a| a.addr.clone())
        .unwrap_or_default();

    let addresses: Vec<models::Address> = xml_host
        .address
        .iter()
        .map(|a| models::Address {
            addr: a.addr.clone(),
            addr_type: a.addrtype.clone().unwrap_or_else(|| "ipv4".to_string()),
        })
        .collect();

    let hostnames: Vec<String> = xml_host
        .hostnames
        .map(|hns| {
            hns.hostname
                .into_iter()
                .filter_map(|hn| hn.name)
                .collect()
        })
        .unwrap_or_default();

    let ports: Vec<models::Port> = xml_host
        .ports
        .map(|p| {
            p.port
                .into_iter()
                .map(|xp| convert_port(xp))
                .collect()
        })
        .unwrap_or_default();

    models::Host {
        ip,
        hostnames,
        status: xml_host.status.state,
        addresses,
        ports,
        os_matches: vec![],
    }
}

fn convert_port(xml_port: XmlPort) -> models::Port {
    let state = xml_port
        .state
        .map(|s| s.state)
        .unwrap_or_else(|| "unknown".to_string());

    let service = xml_port.service.map(|xs| models::Service {
        name: xs.name,
        product: xs.product,
        version: xs.version,
        extra_info: xs.extrainfo,
        tunnel: xs.tunnel,
        hostname: xs.hostname,
        os_type: xs.ostype,
        device_type: xs.devicetype,
        cpe: xs
            .cpe
            .into_iter()
            .filter_map(|c| c.value)
            .filter(|v| !v.trim().is_empty())
            .collect(),
    });

    models::Port {
        port_id: xml_port.portid,
        protocol: xml_port.protocol,
        state,
        service,
    }
}
