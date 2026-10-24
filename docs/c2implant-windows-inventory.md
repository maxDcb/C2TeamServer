# Inventaire de C2Implant (Windows)

Source : [C2Implant](https://github.com/maxDcb/C2Implant), branche `master` au commit [`8a0137a`](https://github.com/maxDcb/C2Implant/tree/8a0137a), consulté le 24 octobre 2026. Le dépôt est maintenu par le propriétaire du projet. Cet inventaire décrit les sources et les cibles déclarées ; il ne valide pas leur fonctionnement.

## Périmètre et compilation

| Élément | Rôle | Source |
| --- | --- | --- |
| Parent CMake Windows | Assemble `core/`, `libs/`, `thirdParty/`, les modules et les beacons ; C++23, configuration Release et runtime MSVC statique | [CMake racine](https://github.com/maxDcb/C2Implant/blob/8a0137a/CMakeLists.txt) |
| Beacons Windows | Cinq transports avec, pour chacun, une cible exécutable et une cible DLL : HTTP/HTTPS, TCP, GitHub, SMB et DNS | [CMake des launchers](https://github.com/maxDcb/C2Implant/blob/8a0137a/beacon/beacon/CMakeLists.txt), [README](https://github.com/maxDcb/C2Implant/blob/8a0137a/README.md) |
| Configuration embarquée | `BeaconConfig.json` transformé en en-tête généré `cryptDef.hpp` par `handleConfig.py` | [configuration](https://github.com/maxDcb/C2Implant/blob/8a0137a/beacon/beacon/BeaconConfig.json), [générateur](https://github.com/maxDcb/C2Implant/blob/8a0137a/beacon/beacon/handleConfig.py) |
| Modules implant | 45 dossiers de modules ajoutés par `core/modules/CMakeLists.txt`, compilés pour le côté implant et copiés dans `Release/Modules` | [CMake des modules](https://github.com/maxDcb/C2Core/blob/108a370/modules/CMakeLists.txt) |
| Build et distribution | CI sur x64, x86 et ARM64 ; livrables `WindowsBeacons/<arch>` et `WindowsModules/<arch>` dans une archive par architecture | [CI](https://github.com/maxDcb/C2Implant/blob/8a0137a/.github/workflows/CI.yml), [Release](https://github.com/maxDcb/C2Implant/blob/8a0137a/.github/workflows/Release.yml), [contrat TeamServer](implants.md) |

Le TeamServer compile séparément des modules de `core/` pour son propre chargement. Les DLL produites ici sont destinées aux beacons Windows. Les trois parents pointent sur des commits différents de `core/` ; voir l'[inventaire de `core/`](core-inventory.md). Leurs écarts fonctionnels restent à examiner.

## Sous-modules Git

Références de [`.gitmodules`](https://github.com/maxDcb/C2Implant/blob/8a0137a/.gitmodules) et du commit parent `8a0137a`.

| Sous-module | Commit épinglé | Usage dans le parent | Maintenance communiquée |
| --- | --- | --- | --- |
| [`core/`](https://github.com/maxDcb/C2Core) | `108a370` | Base du beacon, transports et modules partagés | Toi |
| [`libs/libDns/`](https://github.com/maxDcb/Dnscommunication) | `3a46f1d` | Client DNS | Toi |
| [`libs/libSocketHandler/`](https://github.com/maxDcb/libSocketHandler) | `b6ec602` | Transport TCP | Toi |
| [`libs/libSocks5/`](https://github.com/maxDcb/libSocks5) | `6a35ed4` | Tunnel SOCKS | Toi |
| [`libs/libPipeHandler/`](https://github.com/maxDcb/libPipeHandler) | `187c023` | Transport SMB / pipe | Toi |
| [`thirdParty/base64/`](https://github.com/ReneNyffenegger/cpp-base64) | `951de60` | Encodage base64, cible locale `c2_base64` | Bibliothèque tierce standard |
| [`thirdParty/donut/`](https://github.com/maxDcb/donut) | `cddbff4` | Bibliothèque Donut locale, notamment pour certaines cibles de modules et tests | Ton fork, avec mises à jour par rapport au dépôt officiel |
| [`thirdParty/MemoryModule/`](https://github.com/maxDcb/MemoryModule) | `ea88298` | Chargement de modules en mémoire côté beacon | Ton fork |
| [`thirdParty/coffLoader/coffLoader/`](https://github.com/maxDcb/COFFLoader) | `ea17773` | Chargeur COFF utilisé par le module partagé | Ton fork ; semble en retard sur l'amont, à vérifier lors de l'audit |
| [`thirdParty/coffLoader/coffPacker/`](https://github.com/maxDcb/COFFPacker) | `05995ee` | Préparation d'arguments COFF | Ton dépôt |

## Autres dépendances

| Élément | Provenance | Relation au build ou au runtime |
| --- | --- | --- |
| `libssh2/1.11.1` | [Conan](https://github.com/maxDcb/C2Implant/blob/8a0137a/conanfile.txt) | Module `SshExec` de `core/` |
| `nlohmann_json/3.12.0` | [Conan](https://github.com/maxDcb/C2Implant/blob/8a0137a/conanfile.txt) | Configuration et messages partagés |
| Windows SDK, WinHTTP et API système | Plateforme Windows | Transports et opérations Windows de `core/` |
| CMake, Conan 2, Visual Studio 2022, Python | Outils de build | Configuration, compilation et génération de l'en-tête de configuration |
| `UnmanagedPowerShell` | Cité seulement dans le [README](https://github.com/maxDcb/C2Implant/blob/8a0137a/README.md) ; aucun sous-module, import ou lien de build relevé dans le dépôt parent | Référence documentaire à vérifier ; pas une dépendance de build déclarée |

## Fonctionnalités présentes

| ID | Fonctionnalité | Sources principales |
| --- | --- | --- |
| WIN-01 | Cinq familles de beacons et dix cibles binaires (EXE et DLL) | [launchers et CMake](https://github.com/maxDcb/C2Implant/tree/8a0137a/beacon/beacon) |
| WIN-02 | Transport HTTP/HTTPS, y compris les chemins HTTP et WebSocket définis dans la configuration | [BeaconHttp de core](https://github.com/maxDcb/C2Core/blob/108a370/beacon/BeaconHttp.cpp), [configuration](https://github.com/maxDcb/C2Implant/blob/8a0137a/beacon/beacon/BeaconConfig.json) |
| WIN-03 | Transports TCP, GitHub, SMB et DNS | [beacons de core](https://github.com/maxDcb/C2Core/tree/108a370/beacon) |
| WIN-04 | Boucle de check-in, attente, réception de tâches et retour des résultats | [Beacon.cpp](https://github.com/maxDcb/C2Core/blob/108a370/beacon/Beacon.cpp) |
| WIN-05 | Instructions internes : fin de session, intervalle d'attente, listeners enfants TCP/SMB, SOCKS, chargement/déchargement et exécution des modules | [Beacon.hpp](https://github.com/maxDcb/C2Core/blob/108a370/beacon/Beacon.hpp), [Beacon.cpp](https://github.com/maxDcb/C2Core/blob/108a370/beacon/Beacon.cpp) |
| WIN-06 | Sérialisation/chiffrement léger des messages partagés, configuration des modules et métadonnées de session | [Beacon.cpp](https://github.com/maxDcb/C2Core/blob/108a370/beacon/Beacon.cpp), [BeaconConfig.json](https://github.com/maxDcb/C2Implant/blob/8a0137a/beacon/beacon/BeaconConfig.json) |
| WIN-07 | Compilation et distribution de modules Windows issus de `core/` | [CMake racine](https://github.com/maxDcb/C2Implant/blob/8a0137a/CMakeLists.txt), [CMake des modules](https://github.com/maxDcb/C2Core/blob/108a370/modules/CMakeLists.txt) |
| WIN-08 | Production des archives x86, x64 et ARM64 pour import dans la release TeamServer | [workflow Release](https://github.com/maxDcb/C2Implant/blob/8a0137a/.github/workflows/Release.yml), [contrat TeamServer](implants.md) |

Les 45 modules sont listés dans l'[inventaire de `core/`](core-inventory.md) à la version du TeamServer. Leur rattachement exact aux builds Windows, Linux et TeamServer reste à vérifier. La présence d'une cible dans CMake ne constitue pas une validation runtime sur les trois architectures.

## À clarifier pour les audits suivants

- Mesurer l'écart éventuel entre ton fork `COFFLoader` et son dépôt amont.
- Rôle exact d'`UnmanagedPowerShell` par rapport au code de `core/`.
