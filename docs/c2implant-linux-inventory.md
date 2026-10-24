# Inventaire de C2LinuxImplant

Source : dépôt local `C2LinuxImplant` sur `master` au commit [`17bfe61`](https://github.com/maxDcb/C2LinuxImplant/tree/17bfe61) (24 octobre 2026). Des modifications locales existaient dans `majSubmodules.sh` et le checkout de `thirdParty/base64/` ; cet inventaire prend le commit parent comme référence et n'a modifié aucun fichier de ce dépôt. Le dépôt est maintenu par le propriétaire du projet. Cet inventaire décrit les sources et les cibles déclarées, sans audit de fonctionnement.

## Périmètre et compilation

| Élément | Rôle | Source |
| --- | --- | --- |
| Parent CMake Linux | Assemble `core/`, `libs/`, `thirdParty/`, modules et beacons ; C++17, configuration Release et `BUILD_IMPLANT` | [CMake racine](https://github.com/maxDcb/C2LinuxImplant/blob/17bfe61/CMakeLists.txt) |
| Beacons Linux | Cinq exécutables déclarés : HTTP/HTTPS, TCP, GitHub, DNS et une cible SMB construite avec un `PipeHandler` dummy ; SMB est destiné à Windows | [CMake des launchers](https://github.com/maxDcb/C2LinuxImplant/blob/17bfe61/beacon/beacon/CMakeLists.txt), [workflow Release](https://github.com/maxDcb/C2LinuxImplant/blob/17bfe61/.github/workflows/Release.yml) |
| Configuration embarquée | `BeaconConfig.json` transformé en en-tête généré `cryptDef.hpp` par `handleConfig.py` | [configuration](https://github.com/maxDcb/C2LinuxImplant/blob/17bfe61/beacon/beacon/BeaconConfig.json), [générateur](https://github.com/maxDcb/C2LinuxImplant/blob/17bfe61/beacon/beacon/handleConfig.py) |
| Modules implant | 45 dossiers de modules ajoutés par `core/modules/CMakeLists.txt`, compilés côté implant sous forme de bibliothèques `.so` | [CMake des modules](https://github.com/maxDcb/C2Core/blob/2b6dbe4/modules/CMakeLists.txt) |
| Build et distribution | CI Linux avec tests ; archive contenant `LinuxBeacons` et `LinuxModules`, importée sous l'architecture x64 par le TeamServer | [CI](https://github.com/maxDcb/C2LinuxImplant/blob/17bfe61/.github/workflows/CI.yml), [Release](https://github.com/maxDcb/C2LinuxImplant/blob/17bfe61/.github/workflows/Release.yml), [contrat TeamServer](implants.md) |

Le parent Linux compile sa propre variante des sources partagées de `core/`. Le TeamServer et le parent Windows utilisent d'autres commits de `core/` dans les versions relevées ; voir l'[inventaire de `core/`](core-inventory.md). Leurs écarts fonctionnels restent à examiner.

## Sous-modules Git

Références de [`.gitmodules`](https://github.com/maxDcb/C2LinuxImplant/blob/17bfe61/.gitmodules) et du commit parent `17bfe61`.

| Sous-module | Commit épinglé | Usage dans le parent | Maintenance communiquée |
| --- | --- | --- | --- |
| [`core/`](https://github.com/maxDcb/C2Core) | `2b6dbe4` | Base du beacon, transports et modules partagés | Toi |
| [`libs/libDns/`](https://github.com/maxDcb/Dnscommunication) | `3a46f1d` | Client DNS | Toi |
| [`libs/libSocketHandler/`](https://github.com/maxDcb/libSocketHandler) | `b6ec602` | Transport TCP | Toi |
| [`libs/libSocks5/`](https://github.com/maxDcb/libSocks5) | `6a35ed4` | Tunnel SOCKS | Toi |
| [`thirdParty/base64/`](https://github.com/ReneNyffenegger/cpp-base64) | `951de60` | Encodage base64, cible locale `c2_base64` | Bibliothèque tierce standard |
| [`thirdParty/donut/`](https://github.com/maxDcb/donut) | `cddbff4` | Bibliothèque Donut locale, notamment pour certaines cibles de modules et tests | Ton fork, avec mises à jour par rapport au dépôt officiel |

`libs/libMemoryModuleDumy/` et `libs/libPipeHandlerDumy/` sont des dossiers du dépôt parent ajoutés par CMake ; ce ne sont pas des sous-modules Git. Dans [`libPipeHandlerDumy/src/PipeHandler.cpp`](https://github.com/maxDcb/C2LinuxImplant/blob/17bfe61/libs/libPipeHandlerDumy/src/PipeHandler.cpp), les méthodes de connexion, lecture et écriture renvoient `true` sans transporter de données. Cela permet la compilation de la cible SMB, sans fournir de transport SMB Linux.

## Autres dépendances

| Élément | Provenance | Relation au build ou au runtime |
| --- | --- | --- |
| `openssl/3.6.2` | [Conan](https://github.com/maxDcb/C2LinuxImplant/blob/17bfe61/conanfile.txt) | Transport HTTPS et liens Linux |
| `cpp-httplib/0.39.0` | [Conan](https://github.com/maxDcb/C2LinuxImplant/blob/17bfe61/conanfile.txt) | Transport HTTP/HTTPS et WebSocket Linux |
| `libssh2/1.11.1` | [Conan](https://github.com/maxDcb/C2LinuxImplant/blob/17bfe61/conanfile.txt) | Module `SshExec` de `core/` |
| `nlohmann_json/3.12.0` | [Conan](https://github.com/maxDcb/C2LinuxImplant/blob/17bfe61/conanfile.txt) | Configuration et messages partagés |
| `catch2/3.14.0` | [Conan](https://github.com/maxDcb/C2LinuxImplant/blob/17bfe61/conanfile.txt) | Build des tests de `core/` lorsque l'option est activée |
| `libsmbclient-dev` | Paquet système installé par les [workflows CI/CD](https://github.com/maxDcb/C2LinuxImplant/blob/17bfe61/.github/workflows/CI.yml) | Dépendance système de la compilation Linux |
| CMake, Conan 2, compilateur C/C++, Python 3, `make` | Outils de build | Configuration, compilation et génération de l'en-tête de configuration |

## Fonctionnalités présentes

| ID | Fonctionnalité | Sources principales |
| --- | --- | --- |
| LNX-01 | Quatre transports Linux prévus : HTTP/HTTPS, TCP, GitHub et DNS ; une cinquième cible `BeaconSmb` utilise le dummy de compilation | [CMake des launchers](https://github.com/maxDcb/C2LinuxImplant/blob/17bfe61/beacon/beacon/CMakeLists.txt), [dummy PipeHandler](https://github.com/maxDcb/C2LinuxImplant/blob/17bfe61/libs/libPipeHandlerDumy/src/PipeHandler.cpp) |
| LNX-02 | Transport HTTP/HTTPS et WebSocket Linux | [BeaconHttp de core](https://github.com/maxDcb/C2Core/blob/2b6dbe4/beacon/BeaconHttp.cpp), [configuration](https://github.com/maxDcb/C2LinuxImplant/blob/17bfe61/beacon/beacon/BeaconConfig.json) |
| LNX-03 | Transports TCP, GitHub et DNS ; cible SMB déclarée mais reliée au dummy `PipeHandler` | [beacons de core](https://github.com/maxDcb/C2Core/tree/2b6dbe4/beacon), [dummy PipeHandler](https://github.com/maxDcb/C2LinuxImplant/blob/17bfe61/libs/libPipeHandlerDumy/src/PipeHandler.cpp) |
| LNX-04 | Boucle de check-in, attente, réception de tâches et retour des résultats | [Beacon.cpp](https://github.com/maxDcb/C2Core/blob/2b6dbe4/beacon/Beacon.cpp) |
| LNX-05 | Instructions internes : fin de session, intervalle d'attente, listener enfant TCP, SOCKS, chargement/déchargement et exécution des modules ; le chemin listener SMB existe dans `core/` mais utilise ici le dummy | [Beacon.hpp](https://github.com/maxDcb/C2Core/blob/2b6dbe4/beacon/Beacon.hpp), [Beacon.cpp](https://github.com/maxDcb/C2Core/blob/2b6dbe4/beacon/Beacon.cpp) |
| LNX-06 | Sérialisation/chiffrement léger des messages partagés, configuration des modules et métadonnées de session | [Beacon.cpp](https://github.com/maxDcb/C2Core/blob/2b6dbe4/beacon/Beacon.cpp), [BeaconConfig.json](https://github.com/maxDcb/C2LinuxImplant/blob/17bfe61/beacon/beacon/BeaconConfig.json) |
| LNX-07 | Compilation des modules Linux issus de `core/` dans `Release/Modules` | [CMake racine](https://github.com/maxDcb/C2LinuxImplant/blob/17bfe61/CMakeLists.txt), [CMake des modules](https://github.com/maxDcb/C2Core/blob/2b6dbe4/modules/CMakeLists.txt) |
| LNX-08 | Production des livrables Linux pour import dans la release TeamServer | [workflow Release](https://github.com/maxDcb/C2LinuxImplant/blob/17bfe61/.github/workflows/Release.yml), [contrat TeamServer](implants.md) |

Les modules sont listés dans l'[inventaire de `core/`](core-inventory.md) à la version du TeamServer. Aucun transport par fichier ou FIFO distinct n'a été relevé dans les sources et cibles de beacon de ce dépôt. Les `std::queue` de `core/` servent à mettre en attente les tâches et leurs résultats en mémoire ; elles ne constituent pas un transport entre processus.

## À clarifier pour les audits suivants

- Correspondance exacte entre les 45 dossiers de modules compilés, les `.so` publiés et les fonctionnalités disponibles sur Linux.
