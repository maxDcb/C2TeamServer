# État de l'audit des dépendances et sous-modules — 25 octobre 2026

Ce suivi compare les [inventaires du 24 octobre](inventory-index.md) aux changements des 23 et 24 octobre. Il décrit les commits des branches de travail et les contrôles disponibles localement ; il ne vaut pas validation d'une release ni résultat de CI distante.

## Références contrôlées

| Parent | Branche examinée | Commit | `origin/master` | Situation |
| --- | --- | --- | --- | --- |
| TeamServer | `codex/dev-general` | `c37c65c` (avant ce complément documentaire) | `7f843a6` | Branche de travail publiée, non intégrée à `master` |
| Implant Windows | `codex/dependency-updates` | `021c75e` | `8a0137a` | 8 commits de la branche ne sont pas dans `origin/master` |
| Implant Linux | `codex/dependency-updates` | `ea09e74` | `17bfe61` | 7 commits de la branche ne sont pas dans `origin/master` |

Les tableaux détaillés de [l'alignement initial](dependency-version-alignment.md) et des [inventaires par composant](inventory-index.md) restent des photographies des commits antérieurs. Ils ne doivent pas être lus comme les versions actuellement épinglées par ces trois branches.

## Ce qui est établi

| Élément | État au 25 octobre | Preuve ou limite |
| --- | --- | --- |
| Inventaire direct | Réalisé pour TeamServer, client, C2Core, implants Windows/Linux et dépendances complémentaires. | [Index](inventory-index.md) ; l'inventaire des usages internes et des dépendances transitives reste partiel. |
| Six sous-modules communs | Gitlinks identiques dans les trois parents : `core` `067be9f`, `libDns` `4899969`, `libSocketHandler` `abb32a7`, `libSocks5` `945038d`, `donut` `728289d`, `base64` `951de60`. | `scripts/check-submodule-alignment.py` a retourné `OK` pour les six chemins sur les commits ci-dessus. Ce contrôle compare les gitlinks des parents, pas leurs arbres de travail, les builds ni les branches `master` des parents. |
| Sous-modules Windows seuls | L'implant Windows épingle `libPipeHandler` `dddf2c5`, `MemoryModule` `ea88298`, `COFFLoader` `78b9ade` et `COFFPacker` `05995ee`. | Les quatre checkouts pointent sur leur `origin/master` local. Leur présence ne constitue pas un audit de leurs usages ou de leur écart avec leurs projets amont. |
| COFFLoader | L'implant Windows épingle `78b9ade` ; ce commit est publié sur `origin/master` du fork COFFLoader. | `git ls-remote --heads origin master` dans le sous-module. L'écart fonctionnel avec l'amont officiel n'est pas mesuré. |
| Dépendances Conan directes | Mises à jour appliquées : gRPC `1.84.0` côté TeamServer, cpp-httplib `0.62.0` côté TeamServer/Linux, OpenSSL `3.6.5` dans les trois parents, Catch2 `3.16.0` côté Linux. | Manifestes des trois branches et [relevé des mises à jour](external-dependency-updates.md). Le TeamServer suit `conan.lock` ; les deux implants ne suivent toujours pas de lock Conan. |
| Dépendances Python | Versions directes rapprochées entre `pyproject.toml` et `requirements.txt`, Donut épinglé à `728289d`, `agent-core` à `dfa341b`, Python minimum `3.12`. `C2Client/uv.lock` suit les transitives résolues. | [Manifestes](../C2Client/pyproject.toml), [lock](../C2Client/uv.lock). Le `pip check` du venv local ne relève aucune dépendance cassée ; cela ne prouve pas que ce venv a été synchronisé avec le lock. |
| Transports | Audits ciblés DNS, TCP, HTTP/HTTPS et SOCKS5 réalisés avec corrections et tests ; SMB a aussi reçu des corrections ciblées. [SOCKS5](socks5-audit.md) documente son contrat et ses risques résiduels. | Détail ci-dessous. Le [transport GitHub](github-transport-audit.md) a été audité, reste désactivé par défaut et ne doit pas être considéré comme opérationnel. |
| Tests consignés | La passe de mise à jour des dépendances consignait 78/78 CTest TeamServer, 62/62 Linux, 58/58 Windows x64 et 257 tests client. Après les changements UI du 24 octobre, 271 tests client passaient sous WSL. | [Relevé initial](external-dependency-updates.md), tests locaux du client. Ces chiffres C++ précèdent plusieurs corrections de transport et de cycle de vie ; ils ne valident pas à eux seuls les gitlinks finaux. |

## Audits de transport et propagation des versions

Les audits de code ciblés des 23–24 octobre ont produit les corrections suivantes. « Réalisé » désigne ici l'examen du contrat et les corrections consignées, pas la validation complète d'une release composée.

| Transport | Périmètre corrigé | Dépôt enfant sur `origin/master` |
| --- | --- | --- |
| DNS | Livraison des messages entre listener et beacon ; contrat de la bibliothèque DNS. | `core` `99620af` puis `067be9f` ; `libDns` `4899969` |
| TCP | Cycle de vie des sockets, liaison des ports, tunnels inactifs, conservation des messages après échec d'envoi. | `core` `8f8f64b` puis `067be9f` ; `libSocketHandler` `abb32a7` |
| HTTP/HTTPS | Check-ins idempotents, état du listener et échanges beacon/listener. | `core` `ae6d0bc` puis `067be9f` ; pas de sous-module HTTP dédié |
| SOCKS5 | Contrat listener–beacon, isolation des routes et générations, bornes de concurrence et de tampons. | `core` `bd9b3aa`, `378dd3e`, `75f888d` puis `067be9f` ; `libSocks5` `945038d` ; [audit détaillé](socks5-audit.md) |

Le 25 octobre, `git ls-remote --heads origin master` confirme les commits finaux `core` `067be9f`, `libDns` `4899969`, `libSocketHandler` `abb32a7` et `libSocks5` `945038d` sur les quatre dépôts enfants. Les branches publiées `codex/dev-general` du TeamServer, `codex/dependency-updates` de l'implant Windows et `codex/dependency-updates` de l'implant Linux épinglent toutes ces quatre versions. Le contrôle `scripts/check-submodule-alignment.py` retourne aussi `OK` pour `donut` et `base64`, soit les six gitlinks communs. Les branches `master` **des trois parents** n'ont pas été mises à jour par cette campagne ; la [validation de release](submodule-release-policy.md) reste ouverte.

### Complément : cycle de vie des sessions

L'[audit GUI ↔ serveur des sessions](session-ui-server-audit.md) a produit le commit candidat C2Core `15adf12`, épinglé par les commits locaux TeamServer `9eb83af`, Windows `9228c2f` et Linux `73f99bb`. Le contrôle d'alignement retourne `OK` pour les six gitlinks communs. Sur ce candidat, les builds passent et les suites CTest sont vertes : TeamServer **103/103**, Linux **86/86**, Windows MSVC **64/64** ; le client Python passe **282 tests**. Le test DNS fonctionnel de C2Core a été corrigé pour initialiser explicitement son listener. Ces résultats valident le gate de code partagé ; l'essai avec beacon réel pendant l'arrêt et après redémarrage serveur, ainsi que la provenance de la release composée, restent ouverts.

## Ce qui reste ouvert

1. **Gate de release composée** : les builds et suites CTest des trois parents passent sur C2Core `15adf12`, comme consigné ci-dessus. Restent les essais d'intégration avec beacon réel, les vérifications de packaging et de provenance prévues par la [procédure](submodule-release-policy.md). Les branches des parents ne sont pas encore intégrées à `master`.
2. **Couverture des audits** : les transports TCP/HTTP/DNS/SMB/SOCKS ont reçu des corrections ciblées ; les 45 modules, les dépôts externes chargés par le client, les champs du protocole et les dépendances transitives ne possèdent pas encore un audit d'usage complet. Le transport GitHub conserve ses blocages documentés.
3. **Reproductibilité** : vérifier une installation fraîche depuis `C2Client/uv.lock`, établir si des locks Conan sont nécessaires pour les implants, et fixer une politique pour les sept URL de modules client encore sans commit dans les fichiers `.conf`. La provenance des archives OpenSSL/zlib embarquées par `ElfDropper` et la compatibilité effective de `pwn==1.0` restent à confirmer.
4. **Preuves de tests manuels** : [`TEST_STATE.md`](TEST_STATE.md) et [`TEST_GAPS.md`](TEST_GAPS.md) sont générés à partir de résultats manuels datés de mai 2026. Ils ne reflètent pas automatiquement les modifications d'octobre ; les scénarios modifiés doivent être réexécutés avant de changer leurs statuts.
5. **Arbres de travail locaux** : lors du contrôle du 25 octobre, le parent Windows contient encore des fichiers non suivis et un état local dans `thirdParty/donut` ; le parent Linux est propre. Le TeamServer contient un répertoire `logs/` non suivi. L'alignement `OK` porte sur les commits parents, pas sur les fichiers locaux non suivis ou modifiés.

L'étape suivante comprend l'[audit des prérogatives par composant](component-prerogatives-audit.md), puis l'attachement des résultats de build, de tests et de fonctionnement aux versions alignées et la mise à jour des statuts `TS`, `CL`, `CORE`, `M`, `WIN` et `LNX` dans les inventaires concernés.

## Angles à ajouter à la campagne

| Priorité | Oubli constaté | Critère de clôture |
| --- | --- | --- |
| Critique | **Provenance de la release composée** : le workflow importe par défaut les releases `latest` des implants. `validate_release.py` contrôle leur structure, mais l'import ne vérifie ni leur commit source ni une empreinte publiée par chaque implant. Le script d'alignement des gitlinks n'est pas appelé par les workflows. | Épingler les deux releases importées, enregistrer leurs commits et empreintes, vérifier leur correspondance avec les gitlinks audités, puis exécuter l'alignement dans le gate de release. Le SHA-256 du bundle TeamServer final ne remplace pas cette preuve d'entrée. |
| Haute | **Installation et authentification** : les tests Argon2id, migration d'anciens hashes, mise à jour, conservation des données et runtime installé existent, mais aucun scénario dédié ne les suit dans [`test-catalog.yaml`](testing/test-catalog.yaml). | Ajouter des cas traçables pour première installation, mise à jour et échec avec retour arrière, reset admin, refus sans fichier d'identifiants, puis consigner un essai sur le bundle final. |
| Haute | **Redémarrage de bout en bout** : les tests unitaires du client couvrent la réauthentification et les tests de jobs couvrent un redémarrage serveur, mais le catalogue ne suit pas le cycle complet client + serveur + beacon avec listener recréé et commande en cours. | Exécuter et enregistrer ce scénario sur les transports retenus, en vérifiant la réconciliation des sessions/listeners, le routage et l'absence de doublon de résultat. |
| Moyenne | **Parité environnement et plateformes** : le workflow de release vérifie `uv.lock`, puis installe le client de test via `pip install -e`, sans prouver que les tests utilisent exactement la résolution verrouillée. Le catalogue énumère x86 et ARM64 sans scénario concret pour ces architectures. | Tester au moins une installation client depuis le lock en CI et définir les validations build/runtime attendues pour Windows x86 et ARM64. |
| Moyenne | **Origine et maintien des dépendances externes** : les URL de modules client, les archives vendored d'`ElfDropper`, les forks et leurs licences/avis de sécurité ne sont pas reliés à un relevé de provenance reproductible. | Produire un inventaire de versions, sources, licences et correctifs connus pour les artefacts réellement livrés, puis associer un responsable et une fréquence de revue. |
