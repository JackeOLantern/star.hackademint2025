# Write‑up — My Little Poney (Certificate Transparency)

## 1. Contexte et objectif
On cherche un flag au format `Star{...}` à partir d’un indice caché dans un **certificat TLS** émis pour un sous‑domaine de `hackademint.org`.  
Le pitch : « J’ai **certifié** mon personnage préféré de *My Little Poney* ». La piste mène naturellement aux **logs Certificate Transparency (CT)**.

## 2. Rappel rapide
- **Certificate Transparency (CT)** publie tous les certificats reconnus par les AC modernes.
- Le **SAN (Subject Alternative Name)** d’un certificat expose les **noms DNS** couverts (souvent l’indice).
- Un hôte peut ne pas répondre en DNS ; le certificat n’en est pas moins **réel et vérifiable** dans CT.

## 3. Méthode
1. Interroger un agrégateur CT (crt.sh / Cert Spotter) pour `*.hackademint.org`.
2. Filtrer/repérer un **sous‑domaine** incluant un **nom de poney MLP** et une **phrase lisible** (ex. `...-rainbowdashmybeloved...`).
3. **Vérifier** via OpenSSL (ou l’UI) que le **SAN** du certificat contient bien ce FQDN.
4. **Extraire** la partie lisible (sans le domaine `hackademint.org` ni le préfixe décoratif s’il y en a un).
5. Rendre le flag : `Star{<message_lisible>}`.

## 4. Preuve / commandes
```bash
# Lister les certificats et afficher les DNS names
curl -s 'https://api.certspotter.com/v1/issuances?domain=hackademint.org&include_subdomains=true&expand=dns_names&expand=cert' | jq -r '.[].dns_names[]' | sort -u

# (Alternative) via crt.sh
curl -s 'https://crt.sh/?q=%25.hackademint.org&output=json' | jq -r '.[].name_value' | sed 's/\n/\n/g' | sort -u

# Afficher le SAN d’un certificat
curl -s "https://crt.sh/?d=<CRT_ID>" | openssl x509 -noout -ext subjectAltName
```

## 5. Résultat (exemple illustratif)
Pour un SAN contenant `star-rainbowdashmybeloved.hackademint.org`, on retient :
```
Star{rainbowdashmybeloved}
```

## 6. Notes
- Ne pas confondre : **cert_sha256** (empreinte du cert) ou **pubkey_sha256** (SPKI) ≠ flag.  
- Le flag est **ASCII** / lisible, inspiré d’un nom de personnage de *My Little Poney*.
