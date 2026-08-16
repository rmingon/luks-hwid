use crate::identifier::Identifier;
use crate::provider::Provider;

/// Identité du processeur via CPUID : vendeur, famille/modèle/stepping et
/// drapeaux de fonctionnalités. Ne produit rien hors x86/x86_64.
pub struct CpuidProvider;

impl CpuidProvider {
    pub fn new() -> Self {
        CpuidProvider
    }
}

impl Default for CpuidProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Provider for CpuidProvider {
    fn name(&self) -> &'static str {
        "cpuid"
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn collect(&self) -> Vec<Identifier> {
        use crate::identifier::IdClass;

        let cpuid = raw_cpuid::CpuId::new();
        let vendor = cpuid
            .get_vendor_info()
            .map(|v| v.as_str().to_owned())
            .unwrap_or_else(|| "unknown-x86".to_owned());

        let leaf1 = raw_cpuid::cpuid!(1);
        // eax : stepping/modèle/famille (+ étendus), bits réservés masqués.
        let fms = leaf1.eax & 0x0FFF_3FFF;
        // ecx : bit 31 (hyperviseur) et bit 27 (OSXSAVE, dépend de CR4,
        // donc du noyau et non du matériel) masqués.
        let ecx = leaf1.ecx & !((1 << 31) | (1 << 27));
        let edx = leaf1.edx;

        let value = format!("{vendor};fms={fms:08x};feat={ecx:08x}:{edx:08x}");
        Identifier::new(IdClass::Cpu, &value).into_iter().collect()
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    fn collect(&self) -> Vec<Identifier> {
        Vec::new()
    }
}
