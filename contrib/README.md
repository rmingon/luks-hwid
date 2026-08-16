# Intégration initramfs

## initramfs-tools (Debian, Ubuntu)

1. Copier le binaire keyscript (musl statique) :

   ```sh
   install -m 0755 luks-hwid /usr/sbin/luks-hwid
   install -m 0755 initramfs-tools/hooks/luks-hwid /etc/initramfs-tools/hooks/luks-hwid
   ```

2. Déclarer le keyscript dans `/etc/crypttab` :

   ```
   # header attaché
   cr_root UUID=xxxxxxxx-... none luks,keyscript=/usr/sbin/luks-hwid

   # header détaché sur la clé USB (mode recommandé)
   cr_root /dev/nvme0n1p2 none luks,keyscript=/usr/sbin/luks-hwid,header=/luks-hwid/header.img
   ```

   En mode détaché, si le chemin `header=` n'existe pas au boot, le keyscript
   monte la clé USB `LUKSHWID` et y cherche `luks-hwid/header.img`.

3. Régénérer l'initramfs :

   ```sh
   update-initramfs -u
   ```

Le binaire est statique : rien d'autre à embarquer. Aucun état d'enrôlement
ne vit dans l'initramfs, l'image reste commune à toutes les machines.

## dracut (Fedora, openSUSE) : EXPÉRIMENTAL

systemd-cryptsetup n'exécute pas les keyscripts crypttab. Le module fourni
contourne via un hook pre-trigger qui écrit la clé dans `/run/luks-hwid.key` ;
l'entrée crypttab de l'initramfs doit référencer ce fichier comme keyfile.

```sh
cp -r dracut/90luks-hwid /usr/lib/dracut/modules.d/
dracut -f
```

Testez ce chemin en machine virtuelle avant de l'adopter ; la voie
initramfs-tools est la voie de référence du projet.
