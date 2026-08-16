#!/bin/bash
# Module dracut pour luks-hwid. EXPÉRIMENTAL.
#
# Attention : dracut avec systemd n'exécute PAS les keyscripts crypttab
# (choix assumé de systemd-cryptsetup). Ce module contourne : un hook
# pre-trigger dérive la clé dans /run/luks-hwid.key, et l'entrée crypttab
# de l'initramfs doit pointer ce fichier comme keyfile :
#
#   /etc/crypttab (généré dans l'initramfs) :
#   cr_root UUID=... /run/luks-hwid.key luks
#
# Installation : copier ce répertoire dans /usr/lib/dracut/modules.d/90luks-hwid
# puis dracut -f.

check() {
    require_binaries /usr/sbin/luks-hwid cryptsetup || return 1
    return 0
}

depends() {
    echo crypt
    return 0
}

install() {
    inst /usr/sbin/luks-hwid /usr/sbin/luks-hwid
    inst_hook pre-trigger 50 "$moddir/luks-hwid-derive.sh"
}
