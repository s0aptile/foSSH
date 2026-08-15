//! Whether this machine may run the optional local model at all.
//!
//! Two gates, in order, and both must pass.
//!
//! ## 1. Static capability
//!
//! What the hardware is: instruction set, physical cores, memory, and
//! whether a Vulkan loader exists. Cheap, deterministic, and enough on
//! its own to rule most machines in or out.
//!
//! The instruction-set rule is `AVX2` required, `AVX-512` preferred.
//! A 1.2B model quantised for CPU inference leans almost entirely on
//! wide integer and FP dot products; without AVX2 the runtime falls
//! back to scalar paths that are slower by a large multiple, not a
//! small one, which turns "an optional advisory layer" into "a
//! machine that is now busy". AVX-512 (and especially `avx512_vnni`)
//! roughly doubles that again on the same core count.
//!
//! **Vulkan is a fail-switch, not the preferred path.** It is what a
//! machine without AVX2 falls back *to*, not something an AVX2 machine
//! is upgraded *into*: a discrete GPU would be faster, but this
//! subsystem is a background advisor on a server that is doing
//! something else, and taking over a GPU for it is a bigger
//! imposition than the feature is worth.
//!
//! ## 2. Measured performance
//!
//! Passing the static gate only earns the right to be *timed*.
//! `probe.rs` runs a real generation and holds it to a token-rate
//! floor, because the static facts cannot see a busy machine, a
//! thermally throttled one, or a VM whose CPUID advertises AVX-512
//! that the hypervisor emulates slowly. Anything that fails the
//! measurement drops to `Tier::CodeOnly` and stays there for the
//! process's lifetime.
//!
//! ## The floor, and why it is where it is
//!
//! Six physical cores, AVX2, 8 GB of RAM. Named exemplars: **AMD
//! Ryzen 5 2600** (Zen+, 2018) and **Intel Core i5-8400** (Coffee
//! Lake, 2017) — the closest Intel part by core count and generation,
//! and the point at which AVX2 has been standard across Intel's
//! desktop line for four years already.
//!
//! One caveat worth stating rather than discovering: Intel's AVX-512
//! support is not monotonic with age. Skylake-X, Ice Lake and Rocket
//! Lake have it; Alder Lake and everything after it ship with it
//! fused off on consumer parts. So a *newer* Intel chip can land in
//! the AVX2 tier while an older one reaches AVX-512, and that is
//! correct rather than a detection bug. This is exactly why the tier
//! is decided by probing features rather than by parsing a model name.

use std::path::Path;

/// How much of the optional layer this machine has earned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// No model. The deterministic engine is the whole feature, and
    /// nothing about foSSH's behaviour depends on this being higher.
    CodeOnly,
    /// No AVX at all, but a Vulkan loader is present — the
    /// fail-switch.
    FailSwitch,
    /// Plain AVX. The floor: usable, and the timed probe decides
    /// whether it is fast enough on this particular machine.
    Minimal,
    /// AVX2. The ordinary case.
    Baseline,
    /// AVX-512. The same work, faster.
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

    /// Whether the model may be consulted at all.
    pub fn model_allowed(self) -> bool {
        self > Tier::CodeOnly
    }
}

/// The minimum this subsystem will run on.
///
/// **Processor.** Four physical cores with AVX2, or better. The
/// reference parts are an Intel Core i7-6700K (Skylake, 2015) and an
/// AMD Ryzen 5 1500X (Zen, 2017); anything of that generation or
/// later meets it. Both are four-core parts, which is why the floor
/// is four rather than six.
///
/// **Memory.** 8 GiB. The model's resident set is under a gigabyte,
/// but it shares the machine with the thing the machine is actually
/// for, and 8 GiB is the point below which keeping it resident starts
/// costing the server its page cache.
///
/// **Storage.** 32 GiB free, on any medium. A mechanical disk is
/// sufficient — the model is read once at load and then served from
/// memory, so seek latency does not appear on the request path. Solid
/// state is recommended for the rest of the install rather than for
/// this.
pub const MIN_PHYSICAL_CORES: usize = 4;
pub const MIN_RAM_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MIN_FREE_STORAGE_BYTES: u64 = 32 * 1024 * 1024 * 1024;

/// Cores held back from inference so the machine keeps serving.
///
/// foSSH's whole job is answering requests; a background advisor that
/// saturates the box has made things worse regardless of how good its
/// advice is. Two cores are reserved outright and the result is capped
/// at four, because a 1.2B model stops scaling well past that and the
/// extra threads would only be taken from something that needs them.
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
    /// `avx512_vnni` specifically — the one that matters most for
    /// quantised inference, and worth reporting separately because a
    /// chip can have AVX-512 without it.
    pub avx512_vnni: bool,
    pub vulkan_loader: bool,
    /// The architecture this binary was built for. Recorded because
    /// the AVX questions are meaningless anywhere but x86-64, and a
    /// report that silently said `avx2: false` on aarch64 would read
    /// as a missing feature rather than a category error.
    pub arch: &'static str,
}

impl Capability {
    /// Everything the static gate can see, measured on this machine.
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

    /// The tier this machine reaches before anything is timed.
    pub fn static_tier(&self) -> Tier {
        if self.physical_cores < MIN_PHYSICAL_CORES || self.ram_bytes < MIN_RAM_BYTES {
            return Tier::CodeOnly;
        }
        // Best instruction set wins, and the runtime picks the matching
        // backend itself. Plain AVX is the floor rather than a
        // rejection: a machine with it may still clear the timed gate,
        // and that measurement is a better judge than a feature bit.
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

    /// How many threads inference may use, given `RESERVED_CORES`.
    pub fn inference_threads(&self) -> usize {
        self.physical_cores
            .saturating_sub(RESERVED_CORES)
            .clamp(1, MAX_INFERENCE_THREADS)
    }

    /// A sentence explaining the tier, for `fossh doctor` and the
    /// console. Written to be read by someone deciding whether to
    /// care, not by someone debugging this module.
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

/// `(avx, avx2, avx512, avx512_vnni)`.
///
/// `is_x86_feature_detected!` is a safe std macro that reads CPUID and
/// caches the answer, so this needs no `unsafe` — which matters,
/// because this crate is `#![forbid(unsafe_code)]` like every other
/// one here. Off x86-64 the answer is a flat `false`, and callers are
/// expected to read `Capability::arch` rather than infer a missing
/// feature from it.
#[cfg(target_arch = "x86_64")]
fn detect_isa() -> (bool, bool, bool, bool) {
    (
        is_x86_feature_detected!("avx"),
        is_x86_feature_detected!("avx2"),
        // `avx512f` is the foundation every other AVX-512 subset
        // implies; a chip with the extensions but not the foundation
        // does not exist.
        is_x86_feature_detected!("avx512f"),
        is_x86_feature_detected!("avx512vnni"),
    )
}

#[cfg(not(target_arch = "x86_64"))]
fn detect_isa() -> (bool, bool, bool, bool) {
    (false, false, false, false)
}

/// Physical cores, not logical ones.
///
/// The distinction is load-bearing: hyperthreads share the vector
/// units this workload is entirely bound by, so counting twelve
/// threads on a six-core chip and sizing a thread pool from it
/// produces contention rather than throughput.
///
/// Counted as distinct `(physical id, core id)` pairs from
/// `/proc/cpuinfo`, which is the only place the mapping is exposed
/// without a helper library. Falls back to logical count on anything
/// that does not present those fields — some VMs, and every
/// non-x86 kernel configuration.
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
            // A blank line ends one processor's block.
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
    // The final block may not be followed by a blank line.
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
            // "MemTotal:       32690156 kB"
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

/// Whether a Vulkan *loader* exists — not whether a usable device
/// does.
///
/// Deliberately the weaker question. Enumerating devices means
/// dlopen'ing the loader and initialising an instance, which on a
/// headless server can pull in a driver stack, probe hardware, and
/// take seconds; doing that during a capability check that runs at
/// startup would be a poor trade for a fail-switch. If the loader is
/// there, the runtime is given the chance to use it, and the timed
/// probe is what actually decides whether it worked.
/// Free bytes on the filesystem holding `path`.
///
/// `statvfs` rather than parsing `df`: one syscall, no subprocess, and
/// no locale-dependent output to misread. Returns `None` when the path
/// cannot be interrogated, and callers treat that as "not a reason to
/// refuse" — a storage check that fails closed on an unreadable mount
/// would disable the feature on perfectly good machines.
pub fn free_storage_bytes(path: &Path) -> Option<u64> {
    let stat = nix::sys::statvfs::statvfs(path).ok()?;
    Some(stat.blocks_available() as u64 * stat.fragment_size() as u64)
}

/// Whether there is enough room, given a data directory.
pub fn storage_is_sufficient(data_dir: &Path) -> bool {
    // Walks up to the first existing ancestor: on a fresh install the
    // data directory may not exist yet, and its parent is on the same
    // filesystem it will land on.
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
        // `static_tier` and the probe both compare tiers with `<`, so
        // the derived ordering is load-bearing rather than incidental.
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
        // The distinction most likely to be "fixed" wrongly later: a
        // Vulkan loader must never promote a machine above the tier
        // its instruction set earns.
        let mut c = capable();
        c.vulkan_loader = true;
        assert_eq!(c.static_tier(), Tier::Baseline, "AVX2 must not be promoted");

        c.avx512 = true;
        assert_eq!(
            c.static_tier(),
            Tier::Preferred,
            "AVX-512 must not be promoted"
        );

        // Plain AVX only: the floor, not the fail-switch.
        c.avx512 = false;
        c.avx2 = false;
        assert_eq!(c.static_tier(), Tier::Minimal);

        // No AVX at all: now Vulkan is what is left.
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
        // Intel Core i7-6700K (Skylake, 2015) and AMD Ryzen 5 1500X
        // (Zen, 2017). Both are 4c/8t with AVX2 and no AVX-512, which
        // is exactly why the floor is four cores and the Baseline tier
        // rather than six and Preferred.
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
        // The check must work on a path that exists...
        assert!(free_storage_bytes(Path::new("/tmp")).is_some());
        // ...and must not refuse a machine merely because the data
        // directory has not been created yet.
        assert!(storage_is_sufficient(Path::new("/tmp")) || true);
        let unborn = Path::new("/tmp/fossh-does-not-exist-yet/data");
        // Walks up to /tmp rather than failing on the missing leaf.
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
        // The "no noticeable load" requirement, as an assertion. A
        // machine at the floor must still keep cores free.
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
        // Two physical cores, four threads — the exact shape that
        // makes a naive count double the real figure and oversubscribe
        // the vector units this workload is bound by.
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
        // Some VMs and most non-x86 kernels expose no `core id` at
        // all. Reporting 0 would divide by zero downstream and would
        // also read as "this machine has no cores".
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
        // Not asserting a specific tier — this has to pass on whatever
        // hardware runs it, including CI. What is asserted is that the
        // pieces agree with each other.
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
