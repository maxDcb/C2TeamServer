# Alignement des versions des dépendances

Relevé du 24 octobre 2026, avant l'audit des usages. Références examinées : `C2TeamServer` `codex/dev-general` `3d7a6e6`, `C2Implant` Windows `master` `8a0137a`, `C2LinuxImplant` `master` `17bfe61`, manifestes du client Python dans le TeamServer. Les SHAs ci-dessous sont ceux épinglés par chaque parent ; ils ne décrivent pas nécessairement la dernière branche par défaut des dépôts enfants.

Ce document conserve le relevé initial. Les versions externes et le minimum Python ont ensuite été modifiés ; voir [la mise à jour des dépendances externes](external-dependency-updates.md) et les manifestes actuels.

## Sous-modules et dépôts maintenus

| Dépendance | TeamServer | Implant Windows | Implant Linux | Client Python | Constat |
| --- | --- | --- | --- | --- | --- |
| `C2Core` | `331f441` | `108a370` | `2b6dbe4` | — | **3 versions** ; Linux a 1 commit de plus que Windows, TeamServer en a 6 de plus que Linux et 7 de plus que Windows |
| `libDns` (`Dnscommunication`) | `3a46f1d` | `3a46f1d` | `3a46f1d` | — | Aligné |
| `libSocketHandler` | `d9ddf06` | `b6ec602` | `b6ec602` | — | **2 versions** ; TeamServer a 1 commit de correction TCP supplémentaire |
| `libSocks5` | `59734b8` | `6a35ed4` | `6a35ed4` | — | **2 versions** ; TeamServer a 1 commit supplémentaire de liaison locale par défaut |
| Fork `donut` | `728289d` | `cddbff4` | `cddbff4` | branche `master` flottante | **2 commits épinglés** ; celui du TeamServer a 1 commit Linux supplémentaire. Au moment du relevé, `master` du fork pointe vers `728289d`, sans garantie pour une installation Python future |
| `libPipeHandler` | —, dummy local | `187c023` | —, dummy local | — | Un seul consommateur réel, Windows |
| Fork `MemoryModule` | —, dummy local | `ea88298` | —, dummy local | — | Un seul consommateur réel, Windows |
| Fork `COFFLoader` | — | `ea17773` | — | — | Un seul consommateur, Windows ; l'écart avec le dépôt amont officiel relève d'une vérification distincte |
| `COFFPacker` | — | `05995ee` | — | — | Un seul consommateur, Windows |
| `agent-core` | — | — | — | `dfa341b` exact | Un seul consommateur, client ; commit sur une branche de développement du dépôt maintenu |

Les quatre écarts de sous-modules partagés suivent une ligne d'ascendance commune ; aucun merge concurrent n'est nécessaire pour rapprocher les commits examinés. En revanche, `C2Core` `331f441`, `libSocketHandler` `d9ddf06` et `libSocks5` `59734b8` sont actuellement sur des branches `codex/` du sous-module, au-delà de leurs branches par défaut. Leur adoption dans les implants exige des builds et tests des deux plateformes avant de déclarer l'alignement validé.

Les dépôts de modules de [`DropperModules.conf`](../C2Client/C2Client/DropperModules.conf) et [`ShellCodeModules.conf`](../C2Client/C2Client/ShellCodeModules.conf) sont consommés par URL sans commit figé. `GoDroplets` est maintenu par un tiers ; tu maintiens son intégration et la version utilisée. Voir le [complément d'inventaire](remaining-dependencies-inventory.md) pour les sept dépôts.

## Sous-module tiers et bibliothèques embarquées

| Élément | TeamServer | Windows | Linux | Constat |
| --- | --- | --- | --- | --- |
| `cpp-base64` | `82147d6` | `951de60` | `951de60` | Deux commits d'écart ; seul le Makefile change dans cet intervalle |
| cpp-httplib Conan | `0.39.0` | — | `0.39.0` | Versions déclarées identiques ; `ElfDropper` embarque séparément un en-tête `0.18.5` |
| OpenSSL Conan | `3.6.2` | — | `3.6.2` | Versions déclarées identiques ; `ElfDropper` embarque séparément des en-têtes `3.3.1` et des archives dont la provenance reste à vérifier |

## Paquets Conan déclarés

| Paquet | TeamServer | Windows | Linux | État |
| --- | --- | --- | --- | --- |
| `grpc` | 1.78.1 | — | — | TeamServer seul |
| `protobuf` | 6.33.5 | — | — | TeamServer seul côté C++ ; même version déclarée par le client Python |
| `spdlog` | 1.17.0 | — | — | TeamServer seul |
| `cpp-httplib` | 0.39.0 | — | 0.39.0 | Aligné là où déclaré |
| `openssl` | 3.6.2 | — | 3.6.2 | Aligné là où déclaré |
| `nlohmann_json` | 3.12.0 | 3.12.0 | 3.12.0 | Aligné |
| `libssh2` | 1.11.1 | 1.11.1 | 1.11.1 | Aligné ; option `shared=False` dans les trois manifestes |
| `catch2` | — | — | 3.14.0 | Dépendance de tests Linux |

Le TeamServer possède [`conan.lock`](../conan.lock) avec 14 références `requires` et 4 `build_requires`. Aucun lock Conan n'est suivi par les deux dépôts d'implants aux commits examinés. Les versions **directes** communes concordent ; les versions transitives résolues dans les trois builds ne sont donc pas garanties identiques. Le [complément d'inventaire](remaining-dependencies-inventory.md) liste les références supplémentaires du lock TeamServer.

## Paquets pip du client

Les déclarations directes se trouvent dans [`pyproject.toml`](../C2Client/pyproject.toml) et [`requirements.txt`](../C2Client/requirements.txt). Une résolution `pip install --dry-run --ignore-installed -e C2Client` du manifeste actuel s'est terminée sans conflit. Aucun lock pip des dépendances transitives n'est suivi.

| Élément | Version ou référence déclarée | Observation |
| --- | --- | --- |
| `grpcio` | 1.78.0 | Décalage de correctif avec `grpc/1.78.1` de Conan. Les correctifs gRPC ne sont pas nécessairement publiés pour tous les langages ([versionnement gRPC Python](https://pypi.org/project/grpcio/1.78.0/)). `grpcio/1.78.1` est retirée sur [PyPI](https://pypi.org/project/grpcio/1.78.1/) : ne pas chercher un alignement numérique automatique sur cette version |
| `protobuf` | 6.33.5 | Même version que le paquet Conan TeamServer |
| `pycryptodome`, `PyQt6`, `gitpython`, `requests`, `pwn`, `pefile`, `openai` | Épinglés dans les deux manifestes du client | Même version déclarée entre ces deux fichiers ; les consommateurs externes de `pycryptodome`, `pwn` et `pefile` sont listés dans le [complément](remaining-dependencies-inventory.md) |
| `pyqtdarktheme`, `markdown` | Sans version épinglée | Résolution dépendante de la date d'installation |
| `PyYAML>=6,<7`, `setuptools` | Dans `pyproject.toml` seulement | `requirements.txt` ne représente pas exactement le même environnement |
| `pytest`, `pytest-qt` | Versions épinglées | Option `test` de `pyproject.toml`, mais installés sans option dans `requirements.txt` |
| `agent-core` | Commit exact `dfa341b` dans les deux fichiers | Ses huit dépendances directes et l'écart entre ses propres manifestes figurent dans le [complément](remaining-dependencies-inventory.md) |
| `donut-shellcode` | `master` du fork dans les deux fichiers | Référence flottante ; ne garantit pas le même commit que les parents C++ |

Le `.venv` local du client ne prouve pas l'état du manifeste actuel : il contient notamment `GitPython 3.1.45` au lieu de `3.1.61`, `requests 2.32.5` au lieu de `2.33.0`, `openai 3.37.0` au lieu de `3.36.1` et `pytest 8.4.1` au lieu de `9.0.3`. `pip check` y relève des métadonnées installées plus anciennes pour `C2Client` et quatre incohérences ; aucune installation n'a été modifiée pendant ce relevé.

## Suite proposée avant l'audit des usages

1. Choisir une référence commune pour les quatre sous-modules maintenus qui divergent. Les commits TeamServer sont les candidats les plus avancés dans leurs lignées respectives, mais leur adoption par Windows et Linux doit être compilée et testée.
2. Épingler `donut-shellcode` sur le même commit que la version C++ retenue, puis rapprocher les références flottantes des modules client selon la politique de mise à jour souhaitée.
3. Décider si `cpp-base64` doit aussi être aligné ; l'écart relevé concerne seulement son Makefile.
4. Réconcilier les deux déclarations pip, produire un environnement verrouillé et obtenir un `pip check` propre dans un environnement frais. Ajouter des locks Conan aux implants si l'identité des dépendances transitives entre builds est requise.
5. Valider les builds et les échanges TeamServer/client/implants sur les références retenues. L'analyse de la solidité des appels aux sous-modules pourra ensuite démarrer avec une base de versions commune.
