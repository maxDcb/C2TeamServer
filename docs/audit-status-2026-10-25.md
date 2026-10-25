# État de l'audit des dépendances et sous-modules — 25 octobre 2026

Ce suivi compare les [inventaires du 24 octobre](inventory-index.md) aux changements des 23 et 24 octobre. Il décrit les commits des branches de travail et les contrôles disponibles localement ; il ne vaut pas validation d'une release ni résultat de CI distante.

## Références contrôlées

| Parent | Branche examinée | Commit | `origin/master` | Situation |
| --- | --- | --- | --- | --- |
| TeamServer | `codex/dev-general` | `0dd554c` | `7f843a6` | 47 commits de la branche ne sont pas dans `origin/master` |
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
| Transports | Corrections et tests ajoutés pour TCP, HTTP, DNS, SMB et SOCKS5 ; [SOCKS5](socks5-audit.md) documente les risques résiduels. | Commits des 23–24 octobre et tests du code. Le [transport GitHub](github-transport-audit.md) a été audité, reste désactivé par défaut et ne doit pas être considéré comme opérationnel. |
| Tests consignés | La passe de mise à jour des dépendances consignait 78/78 CTest TeamServer, 62/62 Linux, 58/58 Windows x64 et 257 tests client. Après les changements UI du 24 octobre, 271 tests client passaient sous WSL. | [Relevé initial](external-dependency-updates.md), tests locaux du client. Ces chiffres C++ précèdent plusieurs corrections de transport et de cycle de vie ; ils ne valident pas à eux seuls les gitlinks finaux. |

## Ce qui reste ouvert

1. **Gate de publication des sous-modules** : refaire les builds et suites CTest des trois parents sur les commits ci-dessus, puis les vérifications d'intégration et de packaging prévues par la [procédure](submodule-release-policy.md). Les corrections postérieures au relevé de 78/62/58 tests n'ont pas de résultat consolidé dans ces documents. Les branches des parents ne sont pas encore intégrées à `master`.
2. **Couverture des audits** : les transports TCP/HTTP/DNS/SMB/SOCKS ont reçu des corrections ciblées ; les 45 modules, les dépôts externes chargés par le client, les champs du protocole et les dépendances transitives ne possèdent pas encore un audit d'usage complet. Le transport GitHub conserve ses blocages documentés.
3. **Reproductibilité** : vérifier une installation fraîche depuis `C2Client/uv.lock`, établir si des locks Conan sont nécessaires pour les implants, et fixer une politique pour les sept URL de modules client encore sans commit dans les fichiers `.conf`. La provenance des archives OpenSSL/zlib embarquées par `ElfDropper` et la compatibilité effective de `pwn==1.0` restent à confirmer.
4. **Preuves de tests manuels** : [`TEST_STATE.md`](TEST_STATE.md) et [`TEST_GAPS.md`](TEST_GAPS.md) sont générés à partir de résultats manuels datés de mai 2026. Ils ne reflètent pas automatiquement les modifications d'octobre ; les scénarios modifiés doivent être réexécutés avant de changer leurs statuts.
5. **Arbres de travail locaux** : le parent Windows contient des fichiers non suivis et un état local dans `thirdParty/donut` ; le parent Linux contient une modification de `majSubmodules.sh` et un checkout `thirdParty/base64` modifié. L'alignement `OK` porte sur les commits parents, pas sur ces fichiers locaux.

L'étape suivante de l'audit consiste à attacher des résultats de build, de tests et de fonctionnement aux versions alignées, puis à mettre à jour les statuts des fonctions `TS`, `CL`, `CORE`, `M`, `WIN` et `LNX` dans les inventaires concernés.
