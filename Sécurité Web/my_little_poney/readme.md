# My Little Poney (Certificate Transparency)

> « On m'a dit de certifier les choses importantes. J’ai **certifié** mon personnage préféré de *My Little Poney*… et je l’ai mis sur `hackademint.org`. Sauras‑tu le retrouver ? »

## 1. Description

Ce challenge exploite les **logs Certificate Transparency (CT)** pour divulguer un indice caché dans un certificat TLS émis pour un sous‑domaine de `hackademint.org`.  
Le site correspondant peut **ne pas exister en DNS** ; l’information est dans le **certificat**, consigné publiquement (CT).

Points clés :

- **SAN (Subject Alternative Name)** : liste des noms couverts par le certificat (souvent l’indice lisible).
- **SPKI / pubkey** : clé publique du certificat (non nécessaire ici).
- **Empreintes (sha256)** : *non attendues* pour le flag dans cette instance.
- L’énigme demande un **flag lisible (ASCII)**, de type « *leetspeak* 1337, dérivé d’un libellé *My Little Poney* encodé dans un **sous‑domaine** du SAN.

## 2. Démarche de résolution

1. Interroger un agrégateur CT (ex. **crt.sh** ou **Cert Spotter**) pour lister les certificats émis pour `*.hackademint.org`.
2. Repérer l’entrée dont le SAN contient un **nom lié à My Little Poney** (ex. *rainbowdash*, *pinkie*, etc.).
3. **Extraire un message lisible** encodé dans le sous‑domaine (p. ex. `star-rainbowdashmybeloved.hackademint.org` → message « `rainbowdashmybeloved` »).
4. Construire le flag : `Star{<message_lisible>}`.

## 3. Commandes utiles

### Option A — via Cert Spotter (API JSON)
```bash
curl -s 'https://api.certspotter.com/v1/issuances?domain=hackademint.org&include_subdomains=true&expand=dns_names&expand=cert' | jq -r '.[].dns_names[]' | sort -u
```

### Option B — via crt.sh (JSON)
```bash
curl -s 'https://crt.sh/?q=%25.hackademint.org&output=json' | jq -r '.[].name_value' | sed 's/\n/\n/g' | sort -u
```

### Afficher le SAN pour une entrée donnée (preuve)
```bash
# ID obtenu depuis l’agrégateur (ex. crt.sh) :
curl -s "https://crt.sh/?d=<CRT_ID>" | openssl x509 -noout -ext subjectAltName
```

## 4. Résultat (selon l’instance)

Si le SAN contient un hôte de la forme `star-<poney>mybeloved.hackademint.org`, on retient la partie lisible `"<poney>mybeloved"` pour produire :

```
Star{<poney>mybeloved}
```

> Exemple (illustratif) : `star-rainbowdashmybeloved.hackademint.org`  →  `Star{rainbowdashmybeloved}`

## 5. Remarques

- Un certificat **peut exister sans hôte actif** : CT ≠ DNS.
- Les hashs (cert_sha256, pubkey_sha256) **ne sont pas** le flag attendu ici : l’énigme vise un **message humainement lisible** extrait du SAN.
