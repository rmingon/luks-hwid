//! Machine à états du boot. Module PUR : aucune E/S, aucun appel système.
//! Le pilote (keyscript.rs) exécute les `Action` et réinjecte des `Ev`.

/// Raison d'un abandon. Le keyscript sort alors avec un code non nul et
/// cryptsetup repasse en saisie manuelle de passphrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailReason {
    /// Header détaché introuvable (clé USB absente) : rien à ouvrir.
    NoHeader,
    /// Ni quorum d'empreinte, ni keyfile USB valide.
    NoUsableKey,
    /// Transition non prévue : bug, on échoue proprement.
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum St {
    Init,
    /// Header LUKS2 lisible (attaché, ou détaché monté depuis l'USB).
    HeaderReady,
    /// Token luks-hwid présent : ce volume connaît une empreinte.
    TokenLoaded,
    /// Volume vierge ou cloné : à provisionner.
    TokenAbsent,
    /// Matériel trop changé : quorum sous k.
    QuorumFailed,
    /// Keyfile USB trouvé ET vérifié (il ouvre réellement le volume).
    RescueAvailable,
    Done,
    Failed(FailReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ev {
    HeaderFound,
    HeaderMissing,
    TokenFound,
    TokenMissing,
    QuorumMet,
    QuorumNotMet,
    UsbKeyValid,
    UsbKeyAbsentOrInvalid,
    ReenrollOk,
    ReenrollFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    ReadToken,
    CollectAndRecover,
    SearchUsb,
    Reenroll,
    /// Émettre le secret reconstruit depuis l'empreinte (hex, stdout).
    EmitFingerprintKey,
    /// Émettre le contenu du keyfile USB : c'est la clé dont on a la preuve
    /// qu'elle ouvre, même si le ré-enrôlement a échoué en route.
    EmitRescueKey,
    Abort(FailReason),
}

pub fn step(st: St, ev: Ev) -> (St, Action) {
    use Action as A;
    use Ev as E;
    use FailReason as F;
    use St as S;

    match (st, ev) {
        (S::Init, E::HeaderFound) => (S::HeaderReady, A::ReadToken),
        (S::Init, E::HeaderMissing) => (S::Failed(F::NoHeader), A::Abort(F::NoHeader)),

        (S::HeaderReady, E::TokenFound) => (S::TokenLoaded, A::CollectAndRecover),
        (S::HeaderReady, E::TokenMissing) => (S::TokenAbsent, A::SearchUsb),

        (S::TokenLoaded, E::QuorumMet) => (S::Done, A::EmitFingerprintKey),
        (S::TokenLoaded, E::QuorumNotMet) => (S::QuorumFailed, A::SearchUsb),

        (S::TokenAbsent | S::QuorumFailed, E::UsbKeyValid) => {
            (S::RescueAvailable, A::Reenroll)
        }
        (S::TokenAbsent | S::QuorumFailed, E::UsbKeyAbsentOrInvalid) => {
            (S::Failed(F::NoUsableKey), A::Abort(F::NoUsableKey))
        }

        // Le keyfile USB est vérifié : on boote dans les deux cas, l'échec
        // du ré-enrôlement est journalisé et visible dans `status`.
        (S::RescueAvailable, E::ReenrollOk | E::ReenrollFailed) => {
            (S::Done, A::EmitRescueKey)
        }

        _ => (S::Failed(F::Internal), A::Abort(F::Internal)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Action as A;
    use Ev as E;
    use FailReason as F;
    use St as S;

    #[test]
    fn chemin_nominal_empreinte() {
        let (st, a) = step(S::Init, E::HeaderFound);
        assert_eq!((st, a), (S::HeaderReady, A::ReadToken));
        let (st, a) = step(st, E::TokenFound);
        assert_eq!((st, a), (S::TokenLoaded, A::CollectAndRecover));
        let (st, a) = step(st, E::QuorumMet);
        assert_eq!((st, a), (S::Done, A::EmitFingerprintKey));
    }

    #[test]
    fn header_detache_sans_usb() {
        assert_eq!(
            step(S::Init, E::HeaderMissing),
            (S::Failed(F::NoHeader), A::Abort(F::NoHeader))
        );
    }

    #[test]
    fn volume_vierge_provisionne_par_usb() {
        let (st, a) = step(S::HeaderReady, E::TokenMissing);
        assert_eq!((st, a), (S::TokenAbsent, A::SearchUsb));
        let (st, a) = step(st, E::UsbKeyValid);
        assert_eq!((st, a), (S::RescueAvailable, A::Reenroll));
        let (st, a) = step(st, E::ReenrollOk);
        assert_eq!((st, a), (S::Done, A::EmitRescueKey));
    }

    #[test]
    fn quorum_perdu_puis_reenrolement() {
        let (st, a) = step(S::TokenLoaded, E::QuorumNotMet);
        assert_eq!((st, a), (S::QuorumFailed, A::SearchUsb));
        let (st, a) = step(st, E::UsbKeyValid);
        assert_eq!((st, a), (S::RescueAvailable, A::Reenroll));
    }

    #[test]
    fn quorum_perdu_sans_usb_laisse_la_main() {
        assert_eq!(
            step(S::QuorumFailed, E::UsbKeyAbsentOrInvalid),
            (S::Failed(F::NoUsableKey), A::Abort(F::NoUsableKey))
        );
        assert_eq!(
            step(S::TokenAbsent, E::UsbKeyAbsentOrInvalid),
            (S::Failed(F::NoUsableKey), A::Abort(F::NoUsableKey))
        );
    }

    #[test]
    fn reenrolement_rate_boote_quand_meme() {
        assert_eq!(
            step(S::RescueAvailable, E::ReenrollFailed),
            (S::Done, A::EmitRescueKey)
        );
    }

    #[test]
    fn transition_imprevue_echoue_proprement() {
        assert_eq!(
            step(S::Done, E::HeaderFound),
            (S::Failed(F::Internal), A::Abort(F::Internal))
        );
        assert_eq!(
            step(S::Init, E::QuorumMet),
            (S::Failed(F::Internal), A::Abort(F::Internal))
        );
    }
}
