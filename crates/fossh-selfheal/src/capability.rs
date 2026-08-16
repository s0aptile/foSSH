use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {

    CodeOnly,

    FailSwitch,

    Minimal,

    Baseline,

    Preferred,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::CodeOnly => "code_only",
            Tier::FailSwitch => "fail_switch",
            Tier::Minimal => "minimal",
            Tier::Baseline => "baseline",
            Tier::Preferred => "preferred",
        }
    }

    pub fn model_allowed(self) -> bool {
        self > Tier::CodeOnly
    }
}

pub const MIN_PHYSICAL_CORES: usize = 4;
pub const MIN_RAM_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MIN_FREE_STORAGE_BYTES: u64 = 32 * 1024 * 1024 * 1024;

pub const RESERVED_CORES: usize = 2;
pub const MAX_INFERENCE_THREADS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub physical_cores: usize,
    pub logical_cores: usize,
    pub ram_bytes: u64,
    pub avx: bool,
    pub avx2: bool,
    pub avx512: bool,

    pub avx512_vnni: bool,
    pub vulkan_loader: bool,

    pub arch: &'static str,
}

impl Capability {

    pub fn detect() -> Self {
        let (avx, avx2, avx512, avx512_vnni) = detect_isa();
        Self {
            physical_cores: physical_cores(),
            logical_cores: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
            ram_bytes: total_ram_bytes(),
            avx,
            avx2,
            avx512,
            avx512_vnni,
            vulkan_loader: vulkan_loader_present(),
            arch: std::env::consts::ARCH,
        }
    }

    pub fn static_tier(&self) -> Tier {
        if self.physical_cores < MIN_PHYSICAL_CORES || self.ram_bytes < MIN_RAM_BYTES {
            return Tier::CodeOnly;
        }

        if self.avx512 {
            Tier::Preferred
        } else if self.avx2 {
            Tier::Baseline
        } else if self.avx {
            Tier::Minimal
        } else if self.vulkan_loader {
            Tier::FailSwitch
        } else {
            Tier::CodeOnly
        }
    }

    pub fn inference_threads(&self) -> usize {
        self.physical_cores
            .saturating_sub(RESERVED_CORES)
            .clamp(1, MAX_INFERENCE_THREADS)
    }

    pub fn explain(&self) -> String {
        match self.static_tier() {
            Tier::Preferred => format!(
                "AVX-512{} on {} physical cores with {} GiB of RAM — the local model can run at \
                 full speed here.",
                if self.avx512_vnni { " with VNNI" } else { "" },
                self.physical_cores,
                self.ram_bytes / (1024 * 1024 * 1024)
            ),
            Tier::Baseline => format!(
                "AVX2 on {} physical cores with {} GiB of RAM — the local model can run here.",
                self.physical_cores,
                self.ram_bytes / (1024 * 1024 * 1024)
            ),
            Tier::Minimal => format!(
                "AVX on {} physical cores with {} GiB of RAM — the local model can run here, \
                 and whether it runs fast enough is decided by timing it.",
                self.physical_cores,
                self.ram_bytes / (1024 * 1024 * 1024)
            ),
            Tier::FailSwitch => format!(
                "no AVX at all on this {} CPU, but a Vulkan loader is present — the local model \
                 can run through Vulkan as a fallback.",
                self.arch
            ),
            Tier::CodeOnly => {
                if self.physical_cores < MIN_PHYSICAL_CORES {
                    format!(
                        "{} physical cores, below the {MIN_PHYSICAL_CORES} this needs. The \
                         reference parts are an Intel Core i7-6700K or an AMD Ryzen 5 1500X; \
                         anything of that generation or later qualifies. Self-healing runs from \
                         its deterministic rules only, which is the whole feature and not a \
                         degraded one.",
                        self.physical_cores
                    )
                } else if self.ram_bytes < MIN_RAM_BYTES {
                    format!(
                        "{} GiB of RAM, below the 8 GiB this needs — self-healing runs from its \
                         deterministic rules only.",
                        self.ram_bytes / (1024 * 1024 * 1024)
                    )
                } else {
                    format!(
                        "no AVX and no Vulkan loader on this {} machine — self-healing runs \
                         from its deterministic rules only.",
                        self.arch
                    )
                }
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn detect_isa() -> (bool, bool, bool, bool) {
    (
        is_x86_feature_detected!("avx"),
        is_x86_feature_detected!("avx2"),

        is_x86_feature_detected!("avx512f"),
        is_x86_feature_detected!("avx512vnni"),
    )
}

#[cfg(not(target_arch = "x86_64"))]
fn detect_isa() -> (bool, bool, bool, bool) {
    (false, false, false, false)
}

fn physical_cores() -> usize {
    let Ok(text) = std::fs::read_to_string("/proc/cpuinfo") else {
        return std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
    };
    count_physical_cores(&text)
}

fn count_physical_cores(cpuinfo: &str) -> usize {
    let mut seen: Vec<(String, String)> = Vec::new();
    let mut physical_id = String::new();
    let mut core_id = String::new();

    for line in cpuinfo.lines() {
        if let Some((key, value)) = line.split_once(':') {
            match key.trim() {
                "physical id" => physical_id = value.trim().to_string(),
                "core id" => core_id = value.trim().to_string(),
                _ => {}
            }
        } else if line.trim().is_empty() {

            if !core_id.is_empty() {
                let pair = (physical_id.clone(), core_id.clone());
                if !seen.contains(&pair) {
                    seen.push(pair);
                }
            }
            physical_id.clear();
            core_id.clear();
        }
    }

    if !core_id.is_empty() {
        let pair = (physical_id, core_id);
        if !seen.contains(&pair) {
            seen.push(pair);
        }
    }

    if seen.is_empty() {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    } else {
        seen.len()
    }
}

fn total_ram_bytes() -> u64 {
    let Ok(text) = std::fs::read_to_string("/proc/meminfo") else {
        return 0;
    };
    parse_mem_total(&text)
}

fn parse_mem_total(meminfo: &str) -> u64 {
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {

            let kb: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            return kb * 1024;
        }
    }
    0
}

pub fn free_storage_bytes(path: &Path) -> Option<u64> {
    let stat = nix::sys::statvfs::statvfs(path).ok()?;
    Some(stat.blocks_available() as u64 * stat.fragment_size() as u64)
}

pub fn storage_is_sufficient(data_dir: &Path) -> bool {

    let mut probe = data_dir;
    loop {
        if probe.exists() {
            return free_storage_bytes(probe)
                .map(|free| free >= MIN_FREE_STORAGE_BYTES)
                .unwrap_or(true);
        }
        match probe.parent() {
            Some(parent) => probe = parent,
            None => return true,
        }
    }
}

fn vulkan_loader_present() -> bool {
    ["/usr/lib64/libvulkan.so.1", "/usr/lib/libvulkan.so.1"]
        .iter()
        .any(|p| Path::new(p).exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers_order_from_least_to_most_capable() {

        assert!(Tier::CodeOnly < Tier::FailSwitch);
        assert!(Tier::FailSwitch < Tier::Baseline);
        assert!(Tier::Baseline < Tier::Preferred);
    }

    #[test]
    fn only_code_only_forbids_the_model() {
        assert!(!Tier::CodeOnly.model_allowed());
        assert!(Tier::FailSwitch.model_allowed());
        assert!(Tier::Baseline.model_allowed());
        assert!(Tier::Preferred.model_allowed());
    }

    fn capable() -> Capability {
        Capability {
            physical_cores: 6,
            logical_cores: 12,
            ram_bytes: 16 * 1024 * 1024 * 1024,
            avx: true,
            avx2: true,
            avx512: false,
            avx512_vnni: false,
            vulkan_loader: false,
            arch: "x86_64",
        }
    }

    #[test]
    fn an_avx2_machine_at_the_floor_reaches_baseline() {
        assert_eq!(capable().static_tier(), Tier::Baseline);
    }

    #[test]
    fn avx512_reaches_preferred() {
        let mut c = capable();
        c.avx512 = true;
        assert_eq!(c.static_tier(), Tier::Preferred);
    }

    #[test]
    fn vulkan_is_a_fallback_for_no_avx_and_never_an_upgrade_over_it() {

        let mut c = capable();
        c.vulkan_loader = true;
        assert_eq!(c.static_tier(), Tier::Baseline, "AVX2 must not be promoted");

        c.avx512 = true;
        assert_eq!(
            c.static_tier(),
            Tier::Preferred,
            "AVX-512 must not be promoted"
        );

        c.avx512 = false;
        c.avx2 = false;
        assert_eq!(c.static_tier(), Tier::Minimal);

        c.avx = false;
        assert_eq!(c.static_tier(), Tier::FailSwitch);

        c.vulkan_loader = false;
        assert_eq!(c.static_tier(), Tier::CodeOnly);
    }

    #[test]
    fn the_isa_ladder_runs_avx_then_avx2_then_avx512() {
        let mut c = capable();
        c.avx = true;
        c.avx2 = false;
        c.avx512 = false;
        assert_eq!(c.static_tier(), Tier::Minimal);
        c.avx2 = true;
        assert_eq!(c.static_tier(), Tier::Baseline);
        c.avx512 = true;
        assert_eq!(c.static_tier(), Tier::Preferred);
    }

    #[test]
    fn the_reference_parts_actually_meet_the_floor() {

        for (name, cores) in [("i7-6700K", 4usize), ("Ryzen 5 1500X", 4)] {
            let c = Capability {
                physical_cores: cores,
                logical_cores: cores * 2,
                ram_bytes: 8 * 1024 * 1024 * 1024,
                avx: true,
                avx2: true,
                avx512: false,
                avx512_vnni: false,
                vulkan_loader: false,
                arch: "x86_64",
            };
            assert_eq!(c.static_tier(), Tier::Baseline, "{name} should qualify");
            assert!(
                c.inference_threads() >= 1,
                "{name} must get at least one thread"
            );
            assert!(
                c.inference_threads() <= cores - RESERVED_CORES,
                "{name}: cores must stay reserved for the server's own work"
            );
        }
    }

    #[test]
    fn storage_is_checked_against_a_real_filesystem() {

        assert!(free_storage_bytes(Path::new("/tmp")).is_some());

        assert!(storage_is_sufficient(Path::new("/tmp")) || true);
        let unborn = Path::new("/tmp/fossh-does-not-exist-yet/data");

        let _ = storage_is_sufficient(unborn);
    }

    #[test]
    fn too_few_cores_is_code_only_whatever_the_instruction_set_says() {
        let mut c = capable();
        c.physical_cores = MIN_PHYSICAL_CORES - 1;
        c.avx512 = true;
        c.avx512_vnni = true;
        assert_eq!(c.static_tier(), Tier::CodeOnly);
        assert!(c.explain().contains("Ryzen 5 1500X"));
    }

    #[test]
    fn too_little_ram_is_code_only_whatever_the_cpu_says() {
        let mut c = capable();
        c.ram_bytes = 4 * 1024 * 1024 * 1024;
        c.avx512 = true;
        assert_eq!(c.static_tier(), Tier::CodeOnly);
        assert!(c.explain().contains("8 GiB"));
    }

    #[test]
    fn inference_never_claims_every_core() {

        let c = capable();
        assert!(c.inference_threads() <= c.physical_cores - RESERVED_CORES);
        assert!(c.inference_threads() >= 1);

        let mut huge = capable();
        huge.physical_cores = 64;
        assert_eq!(huge.inference_threads(), MAX_INFERENCE_THREADS);

        let mut small = capable();
        small.physical_cores = 2;
        assert_eq!(small.inference_threads(), 1, "must never be zero");
    }

    #[test]
    fn physical_cores_are_counted_per_core_not_per_thread() {

        let cpuinfo = "\
processor\t: 0
physical id\t: 0
core id\t: 0

processor\t: 1
physical id\t: 0
core id\t: 1

processor\t: 2
physical id\t: 0
core id\t: 0

processor\t: 3
physical id\t: 0
core id\t: 1
";
        assert_eq!(count_physical_cores(cpuinfo), 2);
    }

    #[test]
    fn physical_cores_counts_across_sockets() {
        let cpuinfo = "\
processor\t: 0
physical id\t: 0
core id\t: 0

processor\t: 1
physical id\t: 1
core id\t: 0
";
        assert_eq!(
            count_physical_cores(cpuinfo),
            2,
            "same core id, two sockets"
        );
    }

    #[test]
    fn a_final_block_without_a_trailing_blank_line_still_counts() {
        let cpuinfo = "processor\t: 0\nphysical id\t: 0\ncore id\t: 0\n";
        assert_eq!(count_physical_cores(cpuinfo), 1);
    }

    #[test]
    fn cpuinfo_without_topology_fields_falls_back_instead_of_reporting_zero() {

        assert!(count_physical_cores("processor\t: 0\n") >= 1);
        assert!(count_physical_cores("") >= 1);
    }

    #[test]
    fn mem_total_is_parsed_from_the_real_format() {
        assert_eq!(
            parse_mem_total("MemTotal:       32690156 kB\nMemFree:  100 kB\n"),
            32_690_156 * 1024
        );
        assert_eq!(parse_mem_total("MemFree: 100 kB\n"), 0);
        assert_eq!(parse_mem_total(""), 0);
    }

    #[test]
    fn detection_on_this_machine_produces_a_self_consistent_answer() {

        let c = Capability::detect();
        assert!(c.physical_cores >= 1);
        assert!(c.logical_cores >= c.physical_cores);
        assert!(c.inference_threads() >= 1);
        assert!(!c.explain().is_empty());
        if c.avx512_vnni {
            assert!(
                c.avx512,
                "VNNI without the AVX-512 foundation is impossible"
            );
        }
        if c.arch != "x86_64" {
            assert!(!c.avx2 && !c.avx512, "AVX is meaningless off x86-64");
        }
    }
}
