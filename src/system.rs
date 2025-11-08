use anyhow::Result;
use std::{
    fs,
    time::{Duration, SystemTime},
};
use sysinfo::{CpuExt, DiskExt, NetworkExt, ProcessExt, System, SystemExt};
use tracing::info;

#[derive(Debug)]
pub struct SystemInfo {
    system: System,
    last_update: SystemTime,
    update_interval: Duration,
}

impl SystemInfo {
    pub async fn new() -> Result<Self> {
        let mut system = System::new_all();
        system.refresh_all();

        info!("System information initialized");

        Ok(Self {
            system,
            last_update: SystemTime::now(),
            update_interval: Duration::from_secs(1),
        })
    }

    pub async fn refresh(&mut self) -> Result<()> {
        self.system.refresh_all();
        self.last_update = SystemTime::now();
        Ok(())
    }

    pub async fn update(&mut self) -> Result<()> {
        if self
            .last_update
            .elapsed()
            .unwrap_or(Duration::from_secs(u64::MAX))
            >= self.update_interval
        {
            self.system.refresh_cpu();
            self.system.refresh_memory();
            self.system.refresh_disks_list();
            self.system.refresh_networks();
            self.last_update = SystemTime::now();
        }
        Ok(())
    }

    pub fn os_name(&self) -> String {
        self.system
            .long_os_version()
            .or_else(|| self.system.name())
            .unwrap_or_else(|| "Unknown".to_string())
    }

    pub fn kernel_version(&self) -> String {
        self.system.kernel_version().unwrap_or_else(|| "Unknown".to_string())
    }

    pub fn architecture(&self) -> String {
        std::env::consts::ARCH.to_string()
    }

    pub fn cpu_model(&self) -> String {
        self.system
            .cpus()
            .first()
            .map(|cpu| cpu.brand().to_string())
            .unwrap_or_else(|| "Unknown".to_string())
    }

    pub fn cpu_count(&self) -> usize {
        self.system.cpus().len()
    }

    pub fn total_memory(&self) -> u64 {
        self.system.total_memory()
    }

    pub fn used_memory(&self) -> u64 {
        self.system.used_memory()
    }

    pub fn free_memory(&self) -> u64 {
        self.system.available_memory()
    }

    pub fn load_average(&self) -> f64 {
        let load = self.system.load_average();
        load.one
    }

    pub fn uptime(&self) -> Duration {
        Duration::from_secs(self.system.uptime())
    }

    pub fn boot_time(&self) -> String {
        let boot_time = self.system.boot_time();
        if boot_time > 0 {
            let boot = SystemTime::UNIX_EPOCH + Duration::from_secs(boot_time);
            match boot.duration_since(SystemTime::UNIX_EPOCH) {
                Ok(dur) => format!("{}s since epoch", dur.as_secs()),
                Err(_) => "Unknown".to_string(),
            }
        } else {
            "Unknown".to_string()
        }
    }

    pub fn cpu_usage(&self) -> Vec<f32> {
        self.system.cpus().iter().map(|cpu| cpu.cpu_usage()).collect()
    }

    pub fn average_cpu_usage(&self) -> f32 {
        let usages = self.cpu_usage();
        if usages.is_empty() {
            0.0
        } else {
            usages.iter().sum::<f32>() / usages.len() as f32
        }
    }

    pub fn memory_usage_percentage(&self) -> f64 {
        if self.total_memory() == 0 {
            0.0
        } else {
            (self.used_memory() as f64 / self.total_memory() as f64) * 100.0
        }
    }

    pub fn has_hardware_features(&self) -> HardwareFeatures {
        HardwareFeatures {
            rdrand: self.check_cpu_feature("rdrand"),
            rdseed: self.check_cpu_feature("rdseed"),
            smep: self.check_cpu_feature("smep"),
            smap: self.check_cpu_feature("smap"),
            cet: self.check_cpu_feature("cet"),
            tpm: self.check_tpm_presence(),
            kvm: self.check_kvm_support(),
        }
    }

    fn check_cpu_feature(&self, feature: &str) -> bool {
        if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
            cpuinfo.lines().any(|line| line.starts_with("flags") && line.contains(feature))
        } else {
            false
        }
    }

    fn check_tpm_presence(&self) -> bool {
        std::path::Path::new("/dev/tpm0").exists() || std::path::Path::new("/sys/class/tpm/tpm0").exists()
    }

    fn check_kvm_support(&self) -> bool {
        std::path::Path::new("/dev/kvm").exists()
    }

    pub fn get_disk_usage(&self) -> Result<Vec<DiskInfo>> {
        let mut disks = Vec::new();
        for disk in self.system.disks() {
            let info = DiskInfo {
                name: disk.name().to_string_lossy().to_string(),
                mount_point: disk.mount_point().to_string_lossy().to_string(),
                file_system: String::from_utf8_lossy(disk.file_system()).to_string(),
                total_space: disk.total_space(),
                available_space: disk.available_space(),
                is_removable: disk.is_removable(),
            };
            disks.push(info);
        }
        Ok(disks)
    }

    pub fn get_network_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        let mut interfaces = Vec::new();
        for (name, data) in self.system.networks() {
            let info = NetworkInterface {
                name: name.clone(),
                received: data.received(),
                transmitted: data.transmitted(),
                packets_received: data.packets_received(),
                packets_transmitted: data.packets_transmitted(),
                errors_on_received: data.errors_on_received(),
                errors_on_transmitted: data.errors_on_transmitted(),
            };
            interfaces.push(info);
        }
        Ok(interfaces)
    }

    pub fn get_processes_count(&self) -> usize {
        self.system.processes().len()
    }

    pub fn get_nonos_processes(&self) -> Vec<ProcessInfo> {
        self.system
            .processes()
            .iter()
            .filter_map(|(pid, process)| {
                let name = process.name().to_string();
                if name.contains("nonos") || name.contains("qemu") {
                    Some(ProcessInfo {
                        pid: *pid,
                        name,
                        cpu_usage: process.cpu_usage(),
                        memory: process.memory(),
                        virtual_memory: process.virtual_memory(),
                        status: format!("{:?}", process.status()),
                        start_time: process.start_time(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct HardwareFeatures {
    pub rdrand: bool,
    pub rdseed: bool,
    pub smep: bool,
    pub smap: bool,
    pub cet: bool,
    pub tpm: bool,
    pub kvm: bool,
}

#[derive(Debug, Clone)]
pub struct DiskInfo {
    pub name: String,
    pub mount_point: String,
    pub file_system: String,
    pub total_space: u64,
    pub available_space: u64,
    pub is_removable: bool,
}

#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub received: u64,
    pub transmitted: u64,
    pub packets_received: u64,
    pub packets_transmitted: u64,
    pub errors_on_received: u64,
    pub errors_on_transmitted: u64,
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: sysinfo::Pid,
    pub name: String,
    pub cpu_usage: f32,
    pub memory: u64,
    pub virtual_memory: u64,
    pub status: String,
    pub start_time: u64,
}

impl HardwareFeatures {
    pub fn security_score(&self) -> u8 {
        let mut score = 0;
        if self.rdrand {
            score += 1;
        }
        if self.rdseed {
            score += 1;
        }
        if self.smep {
            score += 2;
        }
        if self.smap {
            score += 2;
        }
        if self.cet {
            score += 2;
        }
        if self.tpm {
            score += 3;
        }
        if self.kvm {
            score += 1;
        }
        score
    }

    pub fn is_nonos_compatible(&self) -> bool {
        self.rdrand && (self.smep || self.smap)
    }

    pub fn missing_features(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.rdrand {
            missing.push("RDRAND");
        }
        if !self.rdseed {
            missing.push("RDSEED");
        }
        if !self.smep {
            missing.push("SMEP");
        }
        if !self.smap {
            missing.push("SMAP");
        }
        if !self.cet {
            missing.push("CET");
        }
        if !self.tpm {
            missing.push("TPM");
        }
        if !self.kvm {
            missing.push("KVM");
        }
        missing
    }
}

impl DiskInfo {
    pub fn usage_percentage(&self) -> f64 {
        if self.total_space == 0 {
            0.0
        } else {
            let used = self.total_space.saturating_sub(self.available_space);
            (used as f64 / self.total_space as f64) * 100.0
        }
    }

    pub fn is_almost_full(&self) -> bool {
        self.usage_percentage() > 90.0
    }
}
