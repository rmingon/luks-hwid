//! Partage de secret de Shamir sur GF(256), polynôme x^8+x^4+x^3+x+1 (0x11b).
//!
//! Implémentation volontairement minimale et sans table précalculée :
//! les tailles manipulées (64 octets, n <= 254) rendent le coût négligeable.

use zeroize::Zeroizing;

use crate::error::ShamirError;

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut acc = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            acc ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    acc
}

/// Inverse multiplicatif : a^254 (a != 0).
fn gf_inv(a: u8) -> u8 {
    debug_assert_ne!(a, 0);
    let mut result = 1u8;
    let mut base = a;
    let mut exp = 254u8;
    while exp != 0 {
        if exp & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    result
}

/// Une part : (abscisse, octets), les octets étant zéroïsés au drop.
pub(crate) type Share = (u8, Zeroizing<Vec<u8>>);

/// Découpe `secret` en `n` parts d'abscisses 1..=n ; `k` parts suffisent
/// à le reconstruire, k-1 parts ne donnent aucune information.
pub(crate) fn split(
    secret: &[u8],
    k: u8,
    n: u8,
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
) -> Result<Vec<Share>, ShamirError> {
    if k < 2 || n < k || n > 254 {
        return Err(ShamirError::InvalidParams { k, n });
    }
    let mut shares: Vec<(u8, Zeroizing<Vec<u8>>)> = (1..=n)
        .map(|x| (x, Zeroizing::new(vec![0u8; secret.len()])))
        .collect();

    let mut coeffs = Zeroizing::new(vec![0u8; k as usize - 1]);
    for (pos, &byte) in secret.iter().enumerate() {
        rng.fill_bytes(&mut coeffs);
        for (x, share) in shares.iter_mut() {
            // Horner : a_{k-1} x^{k-1} + ... + a_1 x + secret
            let mut y = 0u8;
            for &c in coeffs.iter().rev() {
                y = gf_mul(y, *x) ^ c;
            }
            y = gf_mul(y, *x) ^ byte;
            share[pos] = y;
        }
    }
    Ok(shares)
}

/// Interpolation de Lagrange en x=0 avec toutes les parts fournies.
/// L'appelant fournit exactement k parts déchiffrées et authentifiées.
pub(crate) fn reconstruct(shares: &[(u8, &[u8])]) -> Result<Zeroizing<Vec<u8>>, ShamirError> {
    if shares.is_empty() {
        return Err(ShamirError::NoShares);
    }
    let len = shares[0].1.len();
    for (x, y) in shares {
        if *x == 0 {
            return Err(ShamirError::InvalidParams {
                k: shares.len() as u8,
                n: *x,
            });
        }
        if y.len() != len {
            return Err(ShamirError::LengthMismatch);
        }
    }
    for (i, (xi, _)) in shares.iter().enumerate() {
        if shares[i + 1..].iter().any(|(xj, _)| xj == xi) {
            return Err(ShamirError::DuplicateShare);
        }
    }

    let mut secret = Zeroizing::new(vec![0u8; len]);
    for (i, (xi, yi)) in shares.iter().enumerate() {
        // l_i(0) = prod_{j!=i} x_j / (x_j - x_i), la soustraction étant XOR
        let mut num = 1u8;
        let mut den = 1u8;
        for (j, (xj, _)) in shares.iter().enumerate() {
            if i == j {
                continue;
            }
            num = gf_mul(num, *xj);
            den = gf_mul(den, *xj ^ *xi);
        }
        let li = gf_mul(num, gf_inv(den));
        for (pos, &y) in yi.iter().enumerate() {
            secret[pos] ^= gf_mul(y, li);
        }
    }
    Ok(secret)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// RNG déterministe (splitmix64) pour les tests uniquement.
    pub(crate) struct TestRng(pub u64);

    impl rand_core::RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl rand_core::CryptoRng for TestRng {}

    fn subsets(n: usize, k: usize) -> Vec<Vec<usize>> {
        let mut out = Vec::new();
        let mut idx: Vec<usize> = (0..k).collect();
        loop {
            out.push(idx.clone());
            let mut i = k as isize - 1;
            while i >= 0 && idx[i as usize] == i as usize + n - k {
                i -= 1;
            }
            if i < 0 {
                return out;
            }
            let i = i as usize;
            idx[i] += 1;
            for j in i + 1..k {
                idx[j] = idx[j - 1] + 1;
            }
        }
    }

    #[test]
    fn gf_proprietes_de_base() {
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "inv({a})");
            assert_eq!(gf_mul(a, 1), a);
            assert_eq!(gf_mul(a, 0), 0);
        }
        // vecteur AES connu : 0x57 * 0x83 = 0xc1
        assert_eq!(gf_mul(0x57, 0x83), 0xc1);
    }

    #[test]
    fn tous_les_sous_ensembles_de_k_reconstruisent() {
        let mut rng = TestRng(42);
        let secret: Vec<u8> = (0..64u8).map(|i| i.wrapping_mul(37) ^ 0x5a).collect();
        let (k, n) = (3u8, 5u8);
        let shares = split(&secret, k, n, &mut rng).unwrap();

        for combo in subsets(n as usize, k as usize) {
            let picked: Vec<(u8, &[u8])> =
                combo.iter().map(|&i| (shares[i].0, &shares[i].1[..])).collect();
            let rebuilt = reconstruct(&picked).unwrap();
            assert_eq!(&rebuilt[..], &secret[..], "sous-ensemble {combo:?}");
        }
    }

    #[test]
    fn moins_de_k_parts_ne_reconstruisent_pas() {
        let mut rng = TestRng(7);
        let secret = vec![0xABu8; 64];
        let shares = split(&secret, 3, 5, &mut rng).unwrap();
        let two: Vec<(u8, &[u8])> = shares[..2].iter().map(|(x, y)| (*x, &y[..])).collect();
        let rebuilt = reconstruct(&two).unwrap();
        assert_ne!(&rebuilt[..], &secret[..]);
    }

    #[test]
    fn parametres_invalides_rejetes() {
        let mut rng = TestRng(1);
        assert!(matches!(
            split(&[1, 2, 3], 1, 3, &mut rng),
            Err(ShamirError::InvalidParams { .. })
        ));
        assert!(matches!(
            split(&[1, 2, 3], 4, 3, &mut rng),
            Err(ShamirError::InvalidParams { .. })
        ));
        assert!(matches!(reconstruct(&[]), Err(ShamirError::NoShares)));
        assert!(matches!(
            reconstruct(&[(1, &[1, 2][..]), (1, &[3, 4][..])]),
            Err(ShamirError::DuplicateShare)
        ));
        assert!(matches!(
            reconstruct(&[(1, &[1, 2][..]), (2, &[3][..])]),
            Err(ShamirError::LengthMismatch)
        ));
    }
}
