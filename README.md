# luks-hwid

> **The machine is the key.**
>
> Unattended LUKS unlock for hardware that never shipped a TPM. Pull the disk
> out and it turns back into what it really is: a brick of random noise.

Every fleet has them: honest desktop towers, aging laptops, fanless industrial
boxes. No TPM 2.0, or a dusty TPM 1.2 nobody can use. On those machines,
full-disk encryption usually costs you one of two things: someone typing a
passphrase at every boot, or a key file sitting in plaintext next to the data
it protects. `luks-hwid` gives you a third option. The machine derives its
own unlock key from what it is made of (RAM serials, CPU identity, mainboard
serial, USB device serials), so it boots hands-free, while a disk that leaves
the chassis has nothing to say to anyone.

```
                     ┌─────────────────────────────────────┐
   RAM serials ───┐  │                                     │
   CPUID ─────────┼──►  any k of n shares decrypted        │
   board serial ──┤  │  ──► secret reconstructed           ├──► LUKS2 keyslot
   product UUID ──┤  │  (Shamir + Argon2id + XChaCha20)    │
   USB serials ───┘  │                                     │
                     └─────────────────────────────────────┘
```

**Why you might want this:**

- **Boots unattended, no TPM required.** Kiosks, servers in a locked room,
  industrial controllers: no human, no passphrase prompt, no plaintext key.
- **Survives hardware repairs.** A threshold scheme (k of n), not a brittle
  hash: swap a RAM stick and the machine still boots. Swap too much at once
  and the USB rescue key re-enrolls the new fingerprint automatically.
- **Self-healing fleet workflow.** Clone one image to fifty machines; each
  one provisions its own fingerprint on first boot from the rescue USB.
- **Stealth mode included.** With a detached header on the USB key, the disk
  itself is indistinguishable from random data. No LUKS header, no keyslot,
  no proof there is anything to decrypt at all.
- **Honest engineering.** Static musl binary, `#![forbid(unsafe_code)]` core,
  keys mlocked and zeroized on every exit path, and a threat model that tells
  you plainly what this does NOT protect against.

## Threat model

> Protects ONLY against the "disk pulled out and mounted on another machine"
> scenario. Does NOT protect against theft of the complete machine: the
> fingerprint is not a secret and the binary sits in cleartext in /boot. This
> is not a replacement for TPM2 (systemd-cryptenroll / clevis); it is a
> fallback for hardware without a TPM. In detached-header mode, the root of
> trust is the USB key, not the fingerprint.

Where it sits, honestly:

| | Passphrase only | Plaintext keyfile | **luks-hwid** | TPM2 |
|---|---|---|---|---|
| Unattended boot | no | yes | **yes** | yes |
| Bare disk is unreadable | yes | no | **yes** | yes |
| Whole machine stolen | protects | no protection | **no protection**¹ | depends (PIN, PCRs) |
| Hardware required | none | none | **none** | TPM2 chip |
| Survives a component swap | yes | yes | **yes (k-of-n quorum)** | PCR re-enrollment |

¹ except in detached-header mode: without the USB key the disk carries no
LUKS header, hence no keyslot to attack, even with the whole machine in hand.

If your machines have a working TPM2, use `systemd-cryptenroll` or `clevis`.
`luks-hwid` is for all the machines that don't.

## Why a threshold scheme instead of hashing the hardware

Hashing the concatenated identifiers is the classic trap: one replaced RAM
stick and the machine never boots again. Instead:

- at enrollment, a random 64-byte secret is split into **n Shamir shares**,
  one per hardware identifier; any k of them reconstruct it;
- each share is encrypted (XChaCha20-Poly1305) under a key derived **from a
  single identifier** with Argon2id and a per-share random salt;
- at boot, identifiers are re-collected, whatever decrypts is used, and
  **k shares out of n are enough**. Replace one component and the machine
  boots. Replace two at once (default k = n-1) and the USB rescue key takes
  over and re-enrolls automatically.

A share only opens with the exact identifier (authenticated AEAD), so a wrong
secret can never be silently reconstructed. The token stores **no identifier
in cleartext**: only 32-bit truncated fingerprints for diagnostics.

## What this project refuses to do

- **No header destruction, no booby traps** triggered by heuristics about
  "suspicious" manual execution. The project is open source; a trap stops no
  attacker and destroys legitimate users' data.
- **No subcommand that prints a key** outside the keyscript contract.

## Architecture

```
crates/
├── luks-hwid-core     pure library: collection + derivation
│                      #![forbid(unsafe_code)], no root calls,
│                      injectable sources, fully unit-tested
└── luks-hwid          CLI binary: enroll, status, keyscript
contrib/
├── initramfs-tools/   Debian/Ubuntu hook (reference integration)
└── dracut/            Fedora/openSUSE module (experimental)
```

### Identifier sources

| Class | Source | Example |
|---|---|---|
| `ram_serial` | SMBIOS type 17 table (`/sys/firmware/dmi/tables/DMI`) | serial of each DIMM |
| `cpu` | CPUID (vendor, family/model/stepping, features) | CPU signature |
| `board_serial` | `/sys/class/dmi/id/board_serial` | mainboard serial |
| `product_uuid` | `/sys/class/dmi/id/product_uuid` | SMBIOS UUID |
| `usb_device` | `/sys/bus/usb/devices/*/{idVendor,idProduct,serial}` | devices with a serial number |

Every source fails clean: absent or unreadable means an empty list, never a
panic. Values are strictly canonicalized (trim, lowercase, deterministic
ordering) and vendor garbage is rejected (`To Be Filled By O.E.M.`,
`Default string`, `0123456789`, fallback UUIDs, runs of zeros...).

Enrollment tip: unplug transient USB devices (phones, thumb drives) before
running `enroll`, so they don't become part of the fingerprint.

### Enrollment state: a LUKS2 token, never the initramfs

State lives in a custom LUKS2 token of type `luks-hwid`, so **it travels with
the disk**. The initramfs is regenerated by `update-initramfs` and shared
across machines: it carries the binary, zero state. Token present = this
volume knows a fingerprint. Token absent = blank volume, to be provisioned.

```json
{
  "type": "luks-hwid",
  "keyslots": ["2"],
  "version": 1,
  "k": 3,
  "kdf": { "algo": "argon2id", "m_cost_kib": 65536, "t_cost": 3, "parallelism": 1 },
  "cipher": "xchacha20-poly1305",
  "created_unix": 1755244800,
  "shares": [
    {
      "idx": 1,
      "class": "ram_serial",
      "hint": "9f3a1c08",
      "salt": "base64…",
      "nonce": "base64…",
      "ct": "base64…"
    }
  ]
}
```

`hint` is the only link to the identifier: 4 bytes of a domain-separated
BLAKE2b. Each share's AAD binds format version, class and position, so shares
from two tokens can never be mixed.

### Boot state machine

```
        boot
         │
         ▼
   header readable? ──no (detached, USB absent)──► FAIL (exit ≠ 0,
         │yes                                       manual passphrase)
         ▼
   luks-hwid token? ──absent───────────────┐
         │present                          │
         ▼                                 ▼
   collect + decrypt shares         LUKSHWID USB key?
         │                                 │
   quorum ≥ k? ──no────────────────────────┤
         │yes                              │
         ▼                        keyfile verified? ──no──► FAIL
   KEY ON STDOUT                           │yes
   (silent boot)                           ▼
                                  automatic re-enrollment
                                  (header backup → new slot →
                                   verify → revoke old slot)
                                           │
                                           ▼
                                  USB KEYFILE ON STDOUT
                                  (boot guaranteed, any failure logged)
```

Every step is logged to `/dev/kmsg`. On total failure the keyscript exits
non-zero and cryptsetup falls back to the manual passphrase: the backup
passphrase always remains a way in.

### Automatic re-enrollment via USB rescue key

If the token is absent (first boot, cloned image) or the quorum drops below k
(hardware change), the keyscript looks for a USB key labeled `LUKSHWID`
carrying `luks-hwid/rescue.key`, then, in this order:

1. **verify** that the keyfile actually opens the volume (it owns its own
   keyslot; the USB key never holds the master key);
2. **back up the header** (`luksHeaderBackup`) BEFORE any write, onto the USB
   key when possible;
3. collect the current machine's fingerprint;
4. **add** the new keyslot, then verify it really opens the volume;
5. **only then** revoke the old fingerprint keyslot and replace the token.

It is a replacement, not a pile-up: LUKS2 tops out at 32 keyslots and a stale
fingerprint must not stay valid. The ordering guarantees that a power cut
leaves at worst two valid keyslots, never zero. And if re-enrollment fails
midway, the already-verified USB keyfile is still emitted: the machine boots,
the failure shows up in kmsg and in `luks-hwid status`.

### Detached header: the recommended mode

With `header=` in crypttab, the LUKS header lives on the USB key and the disk
holds nothing but bytes indistinguishable from random. Without the USB key
there is **no keyslot to attack and no proof a LUKS volume even exists**. The
root of trust becomes the USB key: store it away from the machine. This mode
reuses the same USB key as the rescue flow (`header.img` next to
`rescue.key`).

## Getting started

### 1. Build

```sh
# system binary (enroll/status via libcryptsetup): on the target machine
cargo build --release

# static keyscript binary (musl, no glibc, no libcryptsetup):
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl --no-default-features -p luks-hwid
```

The system build needs the libcryptsetup headers (`libcryptsetup-dev` on
Debian). The musl build needs nothing: at boot, LUKS operations go through
the `cryptsetup` binary already present in the initramfs.

### 2. Prepare the USB rescue key

```sh
mkfs.ext4 -L LUKSHWID /dev/sdX1
mount /dev/sdX1 /mnt
mkdir -p /mnt/luks-hwid
dd if=/dev/urandom of=/mnt/luks-hwid/rescue.key bs=64 count=1
chmod 0400 /mnt/luks-hwid/rescue.key
cryptsetup luksAddKey /dev/nvme0n1p2 /mnt/luks-hwid/rescue.key
```

### 3. Enroll

```sh
# prerequisite: the volume already has a passphrase (enroll REFUSES otherwise)
luks-hwid enroll --device /dev/nvme0n1p2
luks-hwid status --device /dev/nvme0n1p2
```

`enroll` asks for the existing passphrase, collects the fingerprint, picks
k = max(2, n-1) (override with `--threshold`), adds the keyslot and writes
the token. The Argon2id parameters (`--m-cost-kib`, default 64 MiB) are
stored in the token: size them for the RAM available in your initramfs.

### 4. Wire it into the boot

See [contrib/README.md](contrib/README.md) for initramfs-tools (reference)
and dracut (experimental). The crypttab one-liner:

```
cr_root UUID=... none luks,keyscript=/usr/sbin/luks-hwid
```

## Memory hygiene

- `#![forbid(unsafe_code)]` in `luks-hwid-core`;
- the volume secret lives in an mlocked buffer (best effort);
- `zeroize` on every exit path: key buffers, shares and passphrases are wiped
  on drop, which includes panic unwinding;
- identifier values are never displayed: no `Display`, and a `Debug` that
  shows only the truncated fingerprint.

## Development

```sh
cargo test          # canonicalization, Shamir, derivation, state machine
cargo clippy --all-targets
```

The `core` crate builds and tests on any OS (providers take their sysfs root
as a parameter); the full binary targets Linux.

## License

[PolyForm Noncommercial 1.0.0](LICENSE.md): use it, change it, share it, for
any noncommercial purpose. Commercial use requires a separate license from
the authors.
