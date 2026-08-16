//! `status` : confronte le token luks-hwid au matériel courant, sans rien
//! écrire. Lecture via le CLI cryptsetup pour fonctionner dans tous les
//! builds (y compris le binaire musl du keyscript).

use std::path::PathBuf;

use luks_hwid_core::{collect_all, default_providers, diagnose};

use crate::error::Result;
use crate::luks::Luks;

pub fn run(device: PathBuf, header: Option<PathBuf>) -> Result<u8> {
    let luks = Luks::new(device, header);

    let Some((token_id, meta)) = luks.find_hwid_token()? else {
        println!("Aucun token luks-hwid sur ce volume : empreinte non provisionnée.");
        println!("Au prochain boot, la clé USB de secours ({}) déclenchera", crate::rescue::LABEL);
        println!("l'enrôlement automatique, ou lancez `luks-hwid enroll`.");
        return Ok(1);
    };

    let ids = collect_all(&default_providers());
    let d = diagnose(&meta, &ids);

    println!("Token luks-hwid #{token_id}  (format v{}, créé à {})", meta.version, meta.created_unix);
    println!("Keyslot(s) d'empreinte : {}", meta.keyslots.join(", "));
    println!(
        "Quorum : {}/{} parts disponibles, seuil k={}  ->  {}",
        d.available,
        d.n,
        d.k,
        if d.quorum_ok { "OK" } else { "PERDU" }
    );
    println!("Marge avant perte du quorum : {}", d.margin.max(0));
    println!();
    println!("Parts enrôlées :");
    for s in &d.shares {
        println!(
            "  [{}] {:<13} {}  {}",
            s.idx,
            s.class.as_str(),
            s.hint,
            if s.available { "présente" } else { "ORPHELINE (composant absent ou changé)" }
        );
    }
    if !d.unenrolled.is_empty() {
        println!();
        println!("Identifiants présents mais NON enrôlés :");
        for (class, hint) in &d.unenrolled {
            println!("  {:<13} {}", class.as_str(), hint);
        }
    }

    if !d.quorum_ok {
        println!();
        println!("Quorum perdu : au prochain boot, la clé USB de secours sera requise");
        println!("et déclenchera un ré-enrôlement automatique. Vous pouvez aussi");
        println!("ré-enrôler dès maintenant : luks-hwid enroll --device <dev>");
        return Ok(2);
    }
    if d.margin == 0 || !d.unenrolled.is_empty() {
        println!();
        println!("Conseil : un ré-enrôlement rafraîchirait l'empreinte (marge nulle");
        println!("ou matériel non couvert).");
    }
    Ok(0)
}
