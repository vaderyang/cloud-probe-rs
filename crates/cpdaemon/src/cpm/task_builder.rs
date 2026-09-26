//! Strategy → worker task config builder. Port of
//! `cpdaemon/pkg/cpm/worker_task_builder.go`.

use std::collections::{BTreeMap, HashSet};

use crate::common::{fingerprint_uuid_string, labels_to_fingerprint, task_fingerprint_labels};
use crate::error::{Error, Result};
use crate::tool::Tool;
use crate::worker_config::{
    CapturerConfig, CustomReqPatternConfig, GreOutputConfig, LibpcapConfig, OutputConfig,
    PacketSplitConfig, ReqPatternConfig, RotatingFileOutputConfig, TaskConfig, VxlanOutputConfig,
    ZmqOutputConfig, OUTPUT_TYPE_GRE, OUTPUT_TYPE_ROTATING_FILE, OUTPUT_TYPE_VXLAN,
    OUTPUT_TYPE_ZMQ, REQ_PATTERN_TYPE_AUTO, REQ_PATTERN_TYPE_CUSTOM,
};

use super::models::{
    StrategyEntry, PACKET_CHANNEL_TYPE_FILE, PACKET_CHANNEL_TYPE_GRE, PACKET_CHANNEL_TYPE_VXLAN,
    PACKET_CHANNEL_TYPE_ZMQ, REQ_PATTERN_TYPE_AUTO as CPM_REQ_PATTERN_TYPE_AUTO,
    REQ_PATTERN_TYPE_CUSTOM as CPM_REQ_PATTERN_TYPE_CUSTOM,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskType {
    Interface,
    Container,
    KvmInstance,
}

#[derive(Debug, Clone)]
struct TaskItem {
    typ: TaskType,
    nic_name: String,
    netns: String,
    obs_idx: usize,
    dump_sub_dirs: Vec<String>,
}

pub struct WorkerTaskBuilder {
    tool: Tool,
    daemon_uuid: String,
    active_instances: Vec<String>,
    buff_size: u64,

    warnings: Vec<Error>,
    tasks: Vec<TaskConfig>,
}

impl WorkerTaskBuilder {
    pub fn new(
        tool: Tool,
        daemon_uuid: String,
        active_instances: Vec<String>,
        buff_size: u64,
    ) -> Self {
        WorkerTaskBuilder {
            tool,
            daemon_uuid,
            active_instances,
            buff_size,
            warnings: Vec::new(),
            tasks: Vec::new(),
        }
    }

    pub fn add_strategy(&mut self, strategy: &StrategyEntry) {
        // Validate the strategy by building a dummy interface task.
        if self
            .new_task_config(
                strategy,
                &TaskItem {
                    typ: TaskType::Interface,
                    nic_name: "eth0".into(),
                    netns: String::new(),
                    obs_idx: 0,
                    dump_sub_dirs: Vec::new(),
                },
            )
            .is_err()
        {
            let e = self
                .new_task_config(
                    strategy,
                    &TaskItem {
                        typ: TaskType::Interface,
                        nic_name: "eth0".into(),
                        netns: String::new(),
                        obs_idx: 0,
                        dump_sub_dirs: Vec::new(),
                    },
                )
                .unwrap_err();
            self.warnings.push(e);
            return;
        }

        if !strategy.container_ids.is_empty() {
            self.add_container_ids(strategy);
        } else if !strategy.interface_names.is_empty() {
            let names = strategy.interface_names.clone();
            for (i, name) in names.iter().enumerate() {
                self.add_interface_name(strategy, name, i);
            }
        } else if !strategy.instance_names.is_empty() {
            let names = strategy.instance_names.clone();
            for (i, name) in names.iter().enumerate() {
                self.add_instance_name(strategy, name, i);
            }
        }
    }

    fn add_container_ids(&mut self, strategy: &StrategyEntry) {
        let mut idx = 0usize;
        for c_id in &strategy.container_ids {
            let (container_id, nics) = decode_container_id(c_id);
            if container_id.is_empty() {
                self.warnings
                    .push(Error::new(format!("invalid container id: {c_id}")));
                continue;
            }
            match self.tool.get_container_host_pid(&container_id) {
                Ok(host_pid) => {
                    for nic in &nics {
                        self.add_container_id(strategy, host_pid, nic, idx);
                        idx += 1;
                    }
                }
                Err(e) => {
                    self.warnings.push(Error::new(format!(
                        "get container({container_id}) host process id failed: {e}"
                    )));
                    idx += nics.len();
                }
            }
        }
    }

    fn add_container_id(
        &mut self,
        strategy: &StrategyEntry,
        host_pid: i32,
        nic: &str,
        obs_idx: usize,
    ) {
        let item = TaskItem {
            typ: TaskType::Container,
            nic_name: nic.to_string(),
            netns: format!("/proc/{host_pid}/ns/net"),
            obs_idx,
            dump_sub_dirs: vec![host_pid.to_string(), nic.to_string()],
        };
        match self.new_task_config(strategy, &item) {
            Ok(t) => self.tasks.push(t),
            Err(e) => self.warnings.push(e),
        }
    }

    fn add_interface_name(
        &mut self,
        strategy: &StrategyEntry,
        interface_name: &str,
        obs_idx: usize,
    ) {
        let item = TaskItem {
            typ: TaskType::Interface,
            nic_name: interface_name.to_string(),
            netns: String::new(),
            obs_idx,
            dump_sub_dirs: vec![interface_name.to_string()],
        };
        match self.new_task_config(strategy, &item) {
            Ok(t) => self.tasks.push(t),
            Err(e) => self.warnings.push(e),
        }
    }

    fn add_instance_name(&mut self, strategy: &StrategyEntry, instance_name: &str, obs_idx: usize) {
        if !self.active_instances.iter().any(|i| i == instance_name) {
            self.warnings.push(Error::new(format!(
                "instance name not found: {instance_name}"
            )));
            return;
        }
        let ifs = match self.tool.get_kvm_instance_nics(instance_name) {
            Ok(v) => v,
            Err(e) => {
                self.warnings.push(e);
                return;
            }
        };
        if ifs.is_empty() {
            self.warnings.push(Error::new(format!(
                "instance {instance_name} has no interfaces"
            )));
            return;
        }
        let item = TaskItem {
            typ: TaskType::KvmInstance,
            nic_name: ifs[0].clone(),
            netns: String::new(),
            obs_idx,
            dump_sub_dirs: vec![ifs[0].clone()],
        };
        match self.new_task_config(strategy, &item) {
            Ok(t) => self.tasks.push(t),
            Err(e) => self.warnings.push(e),
        }
    }

    fn new_task_config(&self, strategy: &StrategyEntry, item: &TaskItem) -> Result<TaskConfig> {
        let mut task = TaskConfig {
            fingerprint: None,
            req_pattern: None,
            capturer: CapturerConfig {
                ty: crate::worker_config::CAPTURER_TYPE_LIBPCAP.into(),
                libpcap: Some(LibpcapConfig {
                    interface: String::new(),
                    snaplen: None,
                    netns: None,
                    bpf: None,
                    buffer_size_mb: Some(self.buff_size),
                    timeout_ms: None,
                    not_filter_output_hosts: None,
                }),
            },
            outputs: Vec::new(),
        };

        if let (Some(bpf), Some(lp)) = (&strategy.bpf, task.capturer.libpcap.as_mut()) {
            lp.bpf = Some(bpf.clone());
        }

        let startup_args = if let Some(s) = &strategy.startup {
            parse_startup(s, true)
                .map_err(|e| Error::new(format!("parse startup failed: {s}: {e}")))?
        } else {
            StartupArgs::default()
        };

        if let Some(lp) = task.capturer.libpcap.as_mut() {
            if let Some(v) = startup_args.snaplen {
                lp.snaplen = Some(v);
            }
            if let Some(v) = startup_args.timeout {
                lp.timeout_ms = Some(v);
            }
            if is_true(startup_args.nofilter) {
                let allow_no_filter = if item.typ != TaskType::Interface {
                    true
                } else if !matches!(
                    strategy.packet_channel_type.as_str(),
                    PACKET_CHANNEL_TYPE_GRE | PACKET_CHANNEL_TYPE_VXLAN
                ) {
                    false
                } else if startup_args.bind_device.is_none() {
                    false
                } else {
                    startup_args.bind_device.as_deref() != Some(item.nic_name.as_str())
                };
                if !allow_no_filter {
                    return Err(Error::new(
                        "nofilter only allowed when bind_device is set and different from the snoop interface",
                    ));
                }
            }
            lp.not_filter_output_hosts = startup_args.nofilter;
        }

        if let Some(rpt) = &strategy.req_pattern_type {
            match rpt.as_str() {
                x if x == CPM_REQ_PATTERN_TYPE_AUTO => {
                    task.req_pattern = Some(ReqPatternConfig {
                        ty: REQ_PATTERN_TYPE_AUTO.into(),
                        custom: None,
                    });
                }
                x if x == CPM_REQ_PATTERN_TYPE_CUSTOM => {
                    task.req_pattern = Some(ReqPatternConfig {
                        ty: REQ_PATTERN_TYPE_CUSTOM.into(),
                        custom: Some(CustomReqPatternConfig {
                            pattern: strategy.req_pattern.clone(),
                        }),
                    });
                }
                _ => {}
            }
        }

        let mut output = OutputConfig {
            ty: String::new(),
            rate_limit_mbps: None,
            slice: None,
            vxlan: None,
            gre: None,
            zmq: None,
            file: None,
            rotating_file: None,
        };
        if let Some(v) = strategy.slice_len {
            if v > 0 {
                output.slice = Some(v as u64);
            }
        }
        if let Some(v) = strategy.forward_rate_limit {
            if v > 0 {
                output.rate_limit_mbps = Some(v as u64);
            }
        }

        match strategy.packet_channel_type.as_str() {
            PACKET_CHANNEL_TYPE_VXLAN => {
                output.ty = OUTPUT_TYPE_VXLAN.into();
                let mut vx = VxlanOutputConfig {
                    host: strategy.address.clone(),
                    port: strategy.port,
                    capture_time: strategy.cap_time.map(|c| c == 1),
                    vni1: None,
                    vni2: None,
                    bind_device: startup_args.bind_device.clone(),
                    pmtudisc: startup_args.pmtudisc.clone(),
                    split: if strategy.has_packet_split {
                        Some(PacketSplitConfig {
                            max_payload_size: strategy.packet_split_bytes,
                            recalculate_checksum: if strategy.recalculate_checksum {
                                Some(true)
                            } else {
                                None
                            },
                        })
                    } else {
                        None
                    },
                };

                if strategy
                    .api_version
                    .as_deref()
                    .map(|v| v == "v1")
                    .unwrap_or(true)
                {
                    if strategy.has_service_tag {
                        if let Some(tag) = strategy.service_tag {
                            vx.vni1 = Some(tag as u32);
                        } else {
                            vx.vni1 = Some(0xffffff);
                        }
                    } else {
                        vx.vni1 = Some(0xffffff);
                    }
                } else {
                    let mut tag = Vni2Tag {
                        resource_point_direction: 0,
                        observation_point_id: 1,
                        extension_flag: 0,
                        observation_domain_id: 1,
                    };
                    if strategy.has_observation_tag {
                        tag.observation_domain_id = strategy
                            .observation_domain_ids
                            .get(item.obs_idx)
                            .copied()
                            .unwrap_or(1);
                        tag.observation_point_id = strategy
                            .observation_point_ids
                            .get(item.obs_idx)
                            .map(|v| *v as u32)
                            .unwrap_or(1);
                    }
                    if strategy.has_extension_flag {
                        if let Some(ef) = strategy.extension_flag {
                            tag.extension_flag = (ef as u32) & 0x1;
                        }
                    }
                    vx.vni2 = Some(tag.encode());
                }
                output.vxlan = Some(vx);
            }
            PACKET_CHANNEL_TYPE_GRE => {
                output.ty = OUTPUT_TYPE_GRE.into();
                output.gre = Some(GreOutputConfig {
                    host: strategy.address.clone(),
                    service_tag: if strategy.has_service_tag {
                        strategy.service_tag.map(|v| v as u32)
                    } else {
                        None
                    },
                    bind_device: startup_args.bind_device.clone(),
                    pmtudisc: startup_args.pmtudisc.clone(),
                });
            }
            PACKET_CHANNEL_TYPE_ZMQ => {
                output.ty = OUTPUT_TYPE_ZMQ.into();
                let Some(port) = strategy.port else {
                    return Err(Error::new("missing zmq.port"));
                };
                output.zmq = Some(ZmqOutputConfig {
                    host: strategy.address.clone(),
                    port,
                    hwm: startup_args.zmq_hwm,
                    service_tag: if strategy.has_service_tag {
                        strategy.service_tag.map(|v| v as u32)
                    } else {
                        None
                    },
                    uuid: self.daemon_uuid.clone(),
                    heartbeat_ms: strategy.zmq_heartbeat_ms,
                });
            }
            PACKET_CHANNEL_TYPE_FILE => {
                output.ty = OUTPUT_TYPE_ROTATING_FILE.into();
                let Some(dump_dir) = &strategy.dump_dir else {
                    return Err(Error::new("missing dumpDir"));
                };
                let mut parts = vec![dump_dir.clone()];
                parts.extend(item.dump_sub_dirs.iter().cloned());
                let file_root = parts.join("/");
                std::fs::create_dir_all(&file_root)
                    .map_err(|e| Error::new(format!("create dump dir failed: {file_root}: {e}")))?;
                output.rotating_file = Some(RotatingFileOutputConfig {
                    file_root,
                    max_file_interval: strategy.dump_interval,
                });
            }
            other => {
                return Err(Error::new(format!(
                    "packet channel type not supported: {other}"
                )));
            }
        }

        task.outputs.push(output);
        if let Some(lp) = task.capturer.libpcap.as_mut() {
            lp.interface = item.nic_name.clone();
            if !item.netns.is_empty() {
                lp.netns = Some(item.netns.clone());
            }
        }
        Ok(task)
    }

    /// Assign deduplicated fingerprints. Port of `build()`.
    pub fn build(&mut self) -> (Vec<TaskConfig>, Vec<Error>) {
        let mut seen: HashSet<String> = HashSet::new();
        for task in &mut self.tasks {
            let mut labels: BTreeMap<String, String> = task_fingerprint_labels(task);
            let mut seq = 1u64;
            loop {
                let fingerprint = fingerprint_uuid_string(labels_to_fingerprint(&labels));
                if !seen.contains(&fingerprint) {
                    seen.insert(fingerprint.clone());
                    task.fingerprint = Some(fingerprint);
                    break;
                }
                labels.insert("_seq".to_string(), seq.to_string());
                seq += 1;
            }
        }
        (
            std::mem::take(&mut self.tasks),
            std::mem::take(&mut self.warnings),
        )
    }
}

fn is_true(v: Option<bool>) -> bool {
    v == Some(true)
}

/// Port of `decodeContainerId`.
pub fn decode_container_id(container_id: &str) -> (String, Vec<String>) {
    let parts: Vec<&str> = container_id.split('_').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return (String::new(), Vec::new());
    }
    let mut nics: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();
    if nics.is_empty() {
        nics = vec!["eth0".to_string()];
    }
    let mut id = parts[0].to_string();
    if let Some(i) = id.find("://") {
        id = id[i + 3..].to_string();
    }
    (id, nics)
}

/// VNI2 tag bit-packing. Port of `Vni2Tag`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Vni2Tag {
    pub resource_point_direction: u32, // 2 bits
    pub observation_point_id: u32,     // 5 bits
    pub extension_flag: u32,           // 1 bit
    pub observation_domain_id: u32,    // 24 bits
}

impl Vni2Tag {
    pub fn encode(&self) -> u32 {
        (self.resource_point_direction & 0x03)
            | (self.observation_point_id & 0x1F) << 2
            | (self.extension_flag & 0x01) << 7
            | (self.observation_domain_id & 0x00FF_FFFF) << 8
    }
}

#[derive(Debug, Default, Clone)]
pub struct StartupArgs {
    pub snaplen: Option<i32>,
    pub timeout: Option<i32>,
    pub bind_device: Option<String>,
    pub pmtudisc: Option<String>,
    pub zmq_hwm: Option<i32>,
    pub nofilter: Option<bool>,
    pub priority: Option<bool>,
    pub cpu: Option<i32>,
}

#[derive(Clone, Copy, PartialEq)]
enum FlagKind {
    Int,
    Str,
    Bool,
}

struct FlagDef {
    long: &'static str,
    short: Option<char>,
    kind: FlagKind,
}

const FLAG_DEFS: &[FlagDef] = &[
    FlagDef {
        long: "snaplen",
        short: Some('s'),
        kind: FlagKind::Int,
    },
    FlagDef {
        long: "timeout",
        short: Some('t'),
        kind: FlagKind::Int,
    },
    FlagDef {
        long: "bind_device",
        short: Some('B'),
        kind: FlagKind::Str,
    },
    FlagDef {
        long: "pmtudisc_option",
        short: Some('M'),
        kind: FlagKind::Str,
    },
    FlagDef {
        long: "zmq_hwm",
        short: None,
        kind: FlagKind::Int,
    },
    FlagDef {
        long: "nofilter",
        short: None,
        kind: FlagKind::Bool,
    },
    FlagDef {
        long: "priority",
        short: Some('p'),
        kind: FlagKind::Bool,
    },
    FlagDef {
        long: "cpu",
        short: None,
        kind: FlagKind::Int,
    },
];

fn find_long(name: &str) -> Option<&'static FlagDef> {
    FLAG_DEFS.iter().find(|d| d.long == name)
}
fn find_short(c: char) -> Option<&'static FlagDef> {
    FLAG_DEFS.iter().find(|d| d.short == Some(c))
}

/// Port of `parseStartup` (pflag subset). `ignore_unknown` stops parsing at the
/// first unknown flag, using the flags parsed so far.
pub fn parse_startup(startup: &str, ignore_unknown: bool) -> Result<StartupArgs> {
    let args = super::utils::split_args(startup).map_err(Error::new)?;
    let mut res = StartupArgs::default();
    let mut changed: HashSet<&'static str> = HashSet::new();

    let mut set = |res: &mut StartupArgs, def: &FlagDef, value: Option<&str>| -> Result<()> {
        match def.kind {
            FlagKind::Bool => {
                let v = match value {
                    None => true,
                    Some(s) => s.parse::<bool>().unwrap_or(true),
                };
                if def.long == "nofilter" {
                    res.nofilter = Some(v);
                } else if def.long == "priority" {
                    res.priority = Some(v);
                }
            }
            FlagKind::Int => {
                let Some(s) = value else {
                    return Err(Error::new(format!(
                        "flag needs an argument: --{}",
                        def.long
                    )));
                };
                let v: i32 = s
                    .parse()
                    .map_err(|_| Error::new(format!("invalid argument for --{}: {s}", def.long)))?;
                match def.long {
                    "snaplen" => res.snaplen = Some(v),
                    "timeout" => res.timeout = Some(v),
                    "zmq_hwm" => res.zmq_hwm = Some(v),
                    "cpu" => res.cpu = Some(v),
                    _ => {}
                }
            }
            FlagKind::Str => {
                let Some(s) = value else {
                    return Err(Error::new(format!(
                        "flag needs an argument: --{}",
                        def.long
                    )));
                };
                match def.long {
                    "bind_device" => res.bind_device = Some(s.to_string()),
                    "pmtudisc_option" => res.pmtudisc = Some(s.to_string()),
                    _ => {}
                }
            }
        }
        changed.insert(def.long);
        Ok(())
    };

    let mut i = 0usize;
    while i < args.len() {
        let a = &args[i];
        let def: &FlagDef;
        let mut inline_val: Option<String> = None;

        if let Some(rest) = a.strip_prefix("--") {
            let (name, val) = match rest.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (rest, None),
            };
            match find_long(name) {
                Some(d) => {
                    def = d;
                    inline_val = val;
                }
                None => {
                    if ignore_unknown {
                        break;
                    }
                    return Err(Error::new(format!("unknown flag: --{name}")));
                }
            }
        } else if a.starts_with('-') && a.len() > 1 {
            let rest = &a[1..];
            let c = rest
                .chars()
                .next()
                .ok_or_else(|| Error::new("empty short flag"))?;
            match find_short(c) {
                Some(d) => {
                    def = d;
                    let after = &rest[c.len_utf8()..];
                    if !after.is_empty() {
                        inline_val = Some(after.trim_start_matches('=').to_string());
                    }
                }
                None => {
                    if ignore_unknown {
                        break;
                    }
                    return Err(Error::new(format!("unknown shorthand flag: {c}")));
                }
            }
        } else {
            i += 1;
            continue;
        }

        let value = match def.kind {
            FlagKind::Bool => inline_val.as_deref(),
            _ => {
                if inline_val.is_some() {
                    inline_val.as_deref()
                } else {
                    i += 1;
                    args.get(i).map(|s| s.as_str())
                }
            }
        };
        set(&mut res, def, value)?;
        i += 1;
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool::Tool;
    use crate::worker_config::CAPTURER_TYPE_LIBPCAP;

    const STRATEGY1: &str = r#"{
        "id":3541,"daemonId":3277,"strategy":[{"sliceLen":0,"startup":"-s 65535 -t 0 --zmq_hwm 2000",
        "forwardRateLimit":null,"buffLimit":64,"bpf":null,"hasServiceTag":false,"serviceTag":null,
        "hasReqPattern":false,"reqPattern":null,"reqPatternType":null,"apiVersion":"v1",
        "hasObservationTag":false,"hasExtensionFlag":false,"extensionFlag":0,"zmqHeartbeatMs":2000,
        "packetChannelType":"ZMQ","address":"127.0.0.1","port":5555,"dumpDir":null,"dumpInterval":null,
        "containerIds":[],"interfaceNames":["eth0"],"instanceNames":[],
        "observationDomainIds":[],"observationPointIds":[]}],
        "cpuLimit":null,"memLimit":null,"version":1,"syncInterval":15}"#;

    const STRATEGY2: &str = r#"{
        "id":3542,"daemonId":3277,"strategy":[{"sliceLen":0,
        "startup":"-s 65535 -t 0 --pmtudisc_option do --bind_device=eth1 --nofilter",
        "forwardRateLimit":256,"buffLimit":64,"bpf":"host 10.1.1.1","hasServiceTag":true,"serviceTag":3456,
        "hasReqPattern":true,"reqPattern":"host nic.eth0 and port 22","reqPatternType":"CUSTOM",
        "apiVersion":"v1","hasObservationTag":false,"hasExtensionFlag":false,"extensionFlag":0,
        "packetChannelType":"GRE","address":"2.2.2.2","dumpDir":null,"dumpInterval":null,
        "containerIds":[],"interfaceNames":["eth0"],"instanceNames":[],
        "observationDomainIds":[],"observationPointIds":[]}],
        "cpuLimit":10,"memLimit":1024,"version":3,"syncInterval":15}"#;

    fn build(json: &str) -> Vec<TaskConfig> {
        let res: crate::cpm::models::SyncStrategyResponse = serde_json::from_str(json).unwrap();
        let mut tb = WorkerTaskBuilder::new(
            Tool::default(),
            "796d506a-46a1-4f4e-bd9a-6075a49ac9f8".into(),
            vec![],
            256,
        );
        for s in &res.strategy {
            tb.add_strategy(s);
        }
        let (tasks, warnings) = tb.build();
        assert!(warnings.is_empty(), "warnings: {:?}", warnings);
        tasks
    }

    #[test]
    fn worker_task_builder_1() {
        let tasks = build(STRATEGY1);
        assert_eq!(tasks.len(), 1);
        let t = &tasks[0];
        assert_eq!(
            t.fingerprint.as_deref(),
            Some("64393037-6336-6262-3137-333739363234")
        );
        let lp = t.capturer.libpcap.as_ref().unwrap();
        assert_eq!(t.capturer.ty, CAPTURER_TYPE_LIBPCAP);
        assert_eq!(lp.interface, "eth0");
        assert_eq!(lp.snaplen, Some(65535));
        assert_eq!(lp.timeout_ms, Some(0));
        assert_eq!(lp.buffer_size_mb, Some(256));
        let z = t.outputs[0].zmq.as_ref().unwrap();
        assert_eq!(z.host, "127.0.0.1");
        assert_eq!(z.port, 5555);
        assert_eq!(z.hwm, Some(2000));
        assert_eq!(z.uuid, "796d506a-46a1-4f4e-bd9a-6075a49ac9f8");
        assert_eq!(z.heartbeat_ms, Some(2000));
    }

    #[test]
    fn worker_task_builder_2() {
        let tasks = build(STRATEGY2);
        assert_eq!(tasks.len(), 1);
        let t = &tasks[0];
        assert_eq!(
            t.fingerprint.as_deref(),
            Some("37303236-3865-3063-6331-353864396635")
        );
        let rp = t.req_pattern.as_ref().unwrap();
        assert_eq!(rp.ty, "custom");
        assert_eq!(
            rp.custom.as_ref().unwrap().pattern.as_deref(),
            Some("host nic.eth0 and port 22")
        );
        let lp = t.capturer.libpcap.as_ref().unwrap();
        assert_eq!(lp.interface, "eth0");
        assert_eq!(lp.snaplen, Some(65535));
        assert_eq!(lp.timeout_ms, Some(0));
        assert_eq!(lp.bpf.as_deref(), Some("host 10.1.1.1"));
        assert_eq!(lp.not_filter_output_hosts, Some(true));
        let o = &t.outputs[0];
        assert_eq!(o.rate_limit_mbps, Some(256));
        let g = o.gre.as_ref().unwrap();
        assert_eq!(g.host, "2.2.2.2");
        assert_eq!(g.service_tag, Some(3456));
        assert_eq!(g.pmtudisc.as_deref(), Some("do"));
        assert_eq!(g.bind_device.as_deref(), Some("eth1"));
    }

    #[test]
    fn dedup_fingerprint() {
        let mut tb = WorkerTaskBuilder::new(Tool::default(), "u".into(), vec![], 256);
        // two structurally identical interface strategies resolve to distinct fingerprints
        let s1: crate::cpm::models::StrategyEntry = serde_json::from_str(
            r#"{"packetChannelType":"GRE","address":"2.2.2.2","interfaceNames":["eth0"]}"#,
        )
        .unwrap();
        let s2: crate::cpm::models::StrategyEntry = serde_json::from_str(
            r#"{"packetChannelType":"GRE","address":"2.2.2.2","interfaceNames":["eth0"]}"#,
        )
        .unwrap();
        tb.add_strategy(&s1);
        tb.add_strategy(&s2);
        let (tasks, _) = tb.build();
        assert_eq!(tasks.len(), 2);
        assert_ne!(tasks[0].fingerprint, tasks[1].fingerprint);
    }

    #[test]
    fn parse_startup_first() {
        let a = parse_startup("", false).unwrap();
        assert!(a.snaplen.is_none() && a.timeout.is_none());
    }

    #[test]
    fn parse_startup_short_and_long() {
        let a = parse_startup(
            "-s 65535 -t 1000 -B eth1 -M do --zmq_hwm 1000 -p --cpu 2 --nofilter",
            false,
        )
        .unwrap();
        assert_eq!(a.snaplen, Some(65535));
        assert_eq!(a.timeout, Some(1000));
        assert_eq!(a.bind_device.as_deref(), Some("eth1"));
        assert_eq!(a.pmtudisc.as_deref(), Some("do"));
        assert_eq!(a.zmq_hwm, Some(1000));
        assert_eq!(a.priority, Some(true));
        assert_eq!(a.cpu, Some(2));
        assert_eq!(a.nofilter, Some(true));

        let b = parse_startup("--snaplen=65535 --timeout=1000 --bind_device=eth1 --pmtudisc_option=do --zmq_hwm=1000 --priority --cpu=2 --nofilter", false).unwrap();
        assert_eq!(b.snaplen, Some(65535));
        assert_eq!(b.cpu, Some(2));
    }

    #[test]
    fn parse_startup_unknown_flag() {
        assert!(parse_startup("--snaplen 65535 --unknown=xxx", false).is_err());
        let a = parse_startup("--snaplen 65535 --unknown=xxx", true).unwrap();
        assert_eq!(a.snaplen, Some(65535));
    }

    #[test]
    fn vni2_tag() {
        assert_eq!(
            Vni2Tag {
                observation_domain_id: 23,
                extension_flag: 1,
                observation_point_id: 6,
                resource_point_direction: 0
            }
            .encode(),
            6040
        );
        assert_eq!(
            Vni2Tag {
                observation_domain_id: 3568,
                extension_flag: 0,
                observation_point_id: 9,
                resource_point_direction: 0
            }
            .encode(),
            913444
        );
    }

    #[test]
    fn decode_container_id_vectors() {
        let cases = [
            ("1234567890abcdef", "1234567890abcdef", vec!["eth0"]),
            ("1234567890abcdef_eth1", "1234567890abcdef", vec!["eth1"]),
            (
                "1234567890abcdef_eth0_eth1",
                "1234567890abcdef",
                vec!["eth0", "eth1"],
            ),
            (
                "docker://1234567890abcdef",
                "1234567890abcdef",
                vec!["eth0"],
            ),
            (
                "docker://1234567890abcdef_eth1",
                "1234567890abcdef",
                vec!["eth1"],
            ),
            (
                "containerd://1234567890abcdef_eth0_eth1",
                "1234567890abcdef",
                vec!["eth0", "eth1"],
            ),
        ];
        for (input, want_id, want_nics) in cases {
            let (id, nics) = decode_container_id(input);
            assert_eq!(id, want_id);
            assert_eq!(nics, want_nics);
        }
    }
}
