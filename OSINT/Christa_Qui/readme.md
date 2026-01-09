# Challenge OSINT — « Lieu » (RD 948 / Passage submersible)

> Objectif : à partir d’une photo unique, identifier **d’où est prise la vue** (lieu exact ou coordonnées), et formater votre réponse selon les règles ci‑dessous.

---

## 1) Présentation rapide

- **Thème** : OSINT géolocalisation (photo unique).
- **Niveau** : accessible → intermédiaire (analyse visuelle + vérifications cartographiques).
- **Contexte visuel** : panneau **D948** et repère **« 94 »** visibles sur une voie littorale submersible.
- **Hypothèse forte à confirmer** : le **Passage du Gois** (Vendée), chaussée submersible reliant **Beauvoir‑sur‑Mer** au **Barbâtre / Île de Noirmoutier**. [Sources](#références)

---

## 2) Livrables attendus

Vous pouvez rendre au choix :

- **Format A (coordonnées)** : `LAT,LON` (WGS84 décimal, 5 décimales mini).  
  *Ex.* `46.92500,-2.12200`
- **Format B (toponymie)** : *Nom du site + commune + département*.  
  *Ex.* `Passage du Gois – côté Beauvoir‑sur‑Mer (Vendée)`
- **Format C (point de vue)** : *côté (continent/île) + repère visuel exact*.  
  *Ex.* `Côté continent (Beauvoir‑sur‑Mer), borne RD 948 avec plaquette hectométrique « 94 », vue vers Noirmoutier`

> **Important** : justifiez brièvement (≤ 5 lignes) la méthode ayant mené à la localisation (indices, recoupements, captures si autorisées).

---

## 3) Étapes de résolution (recommandées)

1. **Observation fine** (sans outil) : relever *D948* (route départementale) et la plaquette *« 94 »* (hectométrique). Déduire une **route littorale vendéenne** connue pour être submersible.
2. **Formuler l’hypothèse** : **Passage du Gois** (chaussée submersible ~**4,2 km**) reliant **Beauvoir‑sur‑Mer** ↔ **Barbâtre (Île de Noirmoutier)**.
3. **Vérifier** avec des **sources ouvertes** (offices, mairie, département) : nature submersible, rattachement **RD 948**, fenêtre de passage liée à la **basse mer**.
4. **Confirmer le marquage** : bornes kilométriques + plaquettes **hectométriques (1–9)** expliquent un numéro **« 94 »**.
5. **Localiser le point de vue** : comparer **axe de la chaussée**, **estran**, **poteaux‑refuge** et signalétique via Google Maps / OpenStreetMap / Géoportail; confronter à des **galeries géolocalisées** (Commons, Flickr).
6. **Validation croisée** : vérifier **orientation** (vers île ou continent) et aménagements; utiliser **Street View**/archives locales si disponibles.
7. **Formater la réponse** (A/B/C) + brève justification.

---

## 4) Indices (progressifs)

- **Indice 1** : « D » = **route départementale** (France).  
- **Indice 2** : la **D948** dessert un **site submersible** célèbre en **Vendée**.  
- **Indice 3** : on traverse le site **1h30 avant** et **1h30 après** la **basse mer** (selon coefficients).  
- **Indice 4** (quasi‑solution) : le site relie **Beauvoir‑sur‑Mer** ↔ **Barbâtre / Île de Noirmoutier**.

---

## 5) Barème (exemple)

- **50 %** : bonne **identification du site** (Passage du Gois, Vendée).  
- **30 %** : précision du **côté** (continent vs île) + **repère concordant** (poteau‑refuge, borne, panneau).  
- **20 %** : **coordonnées** cohérentes (±150 m) **ou** capture cartographique annotée (si autorisée).

---

## 6) Outils & bonnes pratiques

- **Cartographie** : Google Maps, **OpenStreetMap**, **Géoportail** (orthophotos + cadastre).  
- **Images** : Google Images / Bing / Yandex (recherche visuelle).  
- **Banques d’images géolocalisées** : **Wikimedia Commons**, **Flickr**.  
- **Sources locales** : Offices de tourisme, **Mairie de Beauvoir‑sur‑Mer**, **Vendée Tourisme**.

> Pensez à noter les **heures de marée** et les **coefficients** : ils expliquent la fenêtre de franchissement et valident le caractère submersible du site.

---

## 7) Réponse type (exemple)

- **Toponyme** : *Passage du Gois (RD 948), Beauvoir‑sur‑Mer ↔ Barbâtre (Île de Noirmoutier), Vendée*.  
- **Coordonnées de référence** (centre indicatif du site) : **46.925, −2.122**.  
  > Le **point de vue exact** doit être déterminé par comparaison d’axe et de repères (poteaux‑refuge, bornes, signalétique).

---

## 8) Références

- **Île de Noirmoutier – Office du tourisme** : « Le passage du Gois » (route submersible **4,2 km**).  
  Source : https://www.ile-noirmoutier.com/fr/explorer-l-ile/le-passage-du-gois
- **Vendée Tourisme** : « Le Gois » (chaussée ~**4,2 km** reliant Beauvoir‑sur‑Mer à l’île).  
  Source : https://www.vendee-tourisme.com/nos-incontournables/le-gois
- **Mairie de Beauvoir‑sur‑Mer** : « Le Passage du Gois, situé sur la **RD 948** ».  
  Source : https://www.mairie-beauvoirsurmer.fr/decouvrir/le-gois/
- **Go Challans Gois** : fenêtre de passage **± 1h30** autour de la **basse mer**.  
  Source : https://www.gochallansgois.fr/incontournables/passage-du-gois/traverser-le-gois-en-pratique/
- **Wikipédia** : synthèse historique et géographique.  
  Source : https://fr.wikipedia.org/wiki/Passage_du_Gois

---

### Notes pour l’organisateur
- Une **grille de correction** (checklist site/côté/repères/coordonnées) peut être fournie séparément.
- Prévoir une **variante “PDF prêt à imprimer”** pour diffusion en atelier.
- Conserver la **photo source** et, si besoin, un **kit d’indices** distinct (texte).

