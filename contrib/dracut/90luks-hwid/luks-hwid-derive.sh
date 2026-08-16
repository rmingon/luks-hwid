#!/bin/sh
# Hook dracut pre-trigger : dérive la clé d'empreinte dans /run/luks-hwid.key
# pour que systemd-cryptsetup la trouve comme keyfile.
#
# Le périphérique source est lu depuis rd.luks.uuid= sur la ligne de commande
# noyau, ou depuis LUKS_HWID_SOURCE= si fourni.

command -v getarg >/dev/null 2>&1 && SRC_UUID="$(getarg rd.luks.uuid=)" || SRC_UUID=""
SRC="$(getarg luks_hwid.source=)"

if [ -z "$SRC" ] && [ -n "$SRC_UUID" ]; then
    # dracut peut passer l'UUID avec ou sans préfixe luks-
    SRC_UUID="${SRC_UUID#luks-}"
    SRC="/dev/disk/by-uuid/${SRC_UUID}"
fi

if [ -z "$SRC" ]; then
    echo "<4>luks-hwid: aucun périphérique source (rd.luks.uuid ou luks_hwid.source)" > /dev/kmsg
    exit 0
fi

# On attend l'apparition du périphérique (l'udev de l'initramfs tourne déjà).
i=0
while [ ! -e "$SRC" ] && [ "$i" -lt 20 ]; do
    sleep 0.5
    i=$((i + 1))
done

CRYPTTAB_SOURCE="$SRC" CRYPTTAB_NAME="dracut" /usr/sbin/luks-hwid keyscript \
    > /run/luks-hwid.key 2>/dev/null

if [ -s /run/luks-hwid.key ]; then
    chmod 0400 /run/luks-hwid.key
    echo "<6>luks-hwid: clé dérivée dans /run/luks-hwid.key" > /dev/kmsg
else
    rm -f /run/luks-hwid.key
    echo "<4>luks-hwid: dérivation échouée, saisie manuelle" > /dev/kmsg
fi

exit 0
