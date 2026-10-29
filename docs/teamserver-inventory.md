# Inventaire du TeamServer

État du dépôt : `codex/dev-general` à `3d7a6e6` (24 octobre 2026).

Cet inventaire décrit ce qui est présent et relié au TeamServer. Il ne juge pas encore la qualité, la nécessité ou la sécurité des éléments. Les statuts de maintenance ci-dessous reprennent les informations communiquées par le propriétaire du projet ; les éléments non précisés restent à confirmer.

## Périmètre et points d'entrée

| Élément | Rôle | Source |
| --- | --- | --- |
| Exécutable `TeamServer` | Serveur C++ lancé avec `TeamServerConfig.json`, API gRPC et boucle de traitement des résultats | [`teamServer/CMakeLists.txt`](../teamServer/CMakeLists.txt), [`main.cpp`](../teamServer/teamServer/main.cpp), [`TeamServer.cpp`](../teamServer/teamServer/TeamServer.cpp) |
| Contrat opérateur | 23 méthodes gRPC et messages Protobuf partagés avec le client | [`TeamServerApi.proto`](../protocol/TeamServerApi.proto) |
| Transport et commandes partagées | Listeners et définitions des commandes fournis par `core/` | [`teamServer/CMakeLists.txt`](../teamServer/CMakeLists.txt), [`core/modules/CMakeLists.txt`](../core/modules/CMakeLists.txt) |
| Données d'exploitation | Jobs SQLite, coffre d'identifiants, artefacts téléversés, générés et hébergés | [`TeamServerConfig.json`](../teamServer/teamServer/TeamServerConfig.json), [`TeamServerRuntimeConfig.cpp`](../teamServer/teamServer/TeamServerRuntimeConfig.cpp) |

## Dépendances externes

Les versions suivantes sont déclarées dans [`conanfile.txt`](../conanfile.txt). Le build racine les recherche dans [`CMakeLists.txt`](../CMakeLists.txt) ; le verrouillage détaillé est dans [`conan.lock`](../conan.lock).

| Dépendance | Version déclarée | Usage dans le périmètre TeamServer |
| --- | --- | --- |
| gRPC | 1.78.1 | API opérateur et serveur TLS |
| Protobuf | 6.33.5 | Contrat gRPC et sérialisation des messages |
| spdlog | 1.17.0 | Journalisation du serveur et des listeners |
| cpp-httplib | 0.39.0 | Listener HTTP/HTTPS et WebSocket |
| OpenSSL | 3.6.2 | TLS, empreintes et chiffrement du coffre |
| nlohmann/json | 3.12.0 | Configuration, métadonnées et données des jobs/artefacts |
| libssh2 | 1.11.1 | Dépendance du build global pour les modules SSH de `core/` |

Autres dépendances du build ou de l'hôte :

| Élément | Provenance | Usage |
| --- | --- | --- |
| SQLite 3 | Bibliothèque système trouvée par `find_library`, hors `conanfile.txt` | Persistance des jobs et événements dans `jobs.sqlite` |
| zlib | `find_package(ZLIB)` dans le build racine ; pas d'entrée directe dans `conanfile.txt` | Liée à `server_core` |
| `pthread`, `dl`, `rt` | Bibliothèques de la plateforme Linux | Threads, chargement des modules `.so` et liaison du serveur |
| CMake, Conan, compilateur C/C++, `protoc` et plugins gRPC | Outillage de construction | Configuration, génération du protocole et compilation |
| `golang-cfssl` | Paquet système cité dans `docs/build.md` | Génération des certificats par les scripts du dossier `certs/` |

## Sous-modules Git utilisés

Les six références viennent de [`.gitmodules`](../.gitmodules) et de l'arbre Git de `codex/dev-general`.

| Sous-module | Dépôt distant | Commit épinglé | Relation au TeamServer | Maintenu par toi ? |
| --- | --- | --- | --- | --- |
| `core/` | [maxDcb/C2Core](https://github.com/maxDcb/C2Core) | `331f441` | Listeners HTTP(S), TCP, DNS et GitHub ; sessions ; `ModuleCmd`, spécifications et modules compilés ; [inventaire distinct](core-inventory.md) | Oui |
| `libs/libDns/` | [maxDcb/Dnscommunication](https://github.com/maxDcb/Dnscommunication) | `3a46f1d` | Bibliothèque `Dnscommunication` du listener DNS | Oui |
| `libs/libSocketHandler/` | [maxDcb/libSocketHandler](https://github.com/maxDcb/libSocketHandler) | `d9ddf06` | Bibliothèque `SocketHandler` du transport TCP | Oui |
| `libs/libSocks5/` | [maxDcb/libSocks5](https://github.com/maxDcb/libSocks5) | `59734b8` | Bibliothèque `SocksServer` du proxy SOCKS | Oui |
| `thirdParty/base64/` | [ReneNyffenegger/cpp-base64](https://github.com/ReneNyffenegger/cpp-base64) | `82147d6` | Code `c2_base64` lié au transport listener | Non ; bibliothèque tierce standard |
| `thirdParty/donut/` | [maxDcb/donut](https://github.com/maxDcb/donut) | `728289d` | Bibliothèque statique Donut et `aplib64` pour la génération de charges | Fork maintenu par toi, avec des mises à jour par rapport au dépôt officiel |

Les dossiers `libs/libMemoryModuleDumy/` et `libs/libPipeHandlerDumy/` sont dans ce dépôt et ajoutés au build global ; ils **ne sont pas** des sous-modules Git.

## Dépendances de distribution et de données

| Élément | Statut | Rôle | Source |
| --- | --- | --- | --- |
| `C2Implant` et `C2LinuxImplant` | Dépôts externes maintenus par toi, pas sous-modules ; inventaires distincts réalisés | Implémentations Windows et Linux compilant une partie du code et des modules de `core/` pour leurs plateformes ; leurs releases alimentent `WindowsBeacons`, `WindowsModules`, `LinuxBeacons` et `LinuxModules` dans le paquet TeamServer | [`docs/implants.md`](implants.md), [inventaire Windows](c2implant-windows-inventory.md), [inventaire Linux](c2implant-linux-inventory.md) |
| GitHub | Service externe, lorsque le listener GitHub est utilisé | Canal de communication du listener `ListenerGithub` | [`TeamServerListenerSessionService.cpp`](../teamServer/teamServer/TeamServerListenerSessionService.cpp), [`ListenerGithub.cpp`](../core/listener/ListenerGithub.cpp) |
| `TeamServerModules/` et `CommandSpecs/` | Artefacts produits par la compilation locale des modules de `core/` pour le TeamServer | Modules `.so` chargés au démarrage ou par `reloadModules`, catalogue et aide des commandes ; les implants compilent leur propre variante des modules de `core/` | [`TeamServerModuleLoader.cpp`](../teamServer/teamServer/TeamServerModuleLoader.cpp), [`teamServer/CMakeLists.txt`](../teamServer/CMakeLists.txt), [`core/modules/CMakeLists.txt`](../core/modules/CMakeLists.txt) |
| `data/Tools/` et `data/Scripts/` | Emplacements d'artefacts à l'exécution, distincts des modules source de `core/` et du dossier de développement `scripts/` | Fichiers utilisés par les préparateurs du TeamServer et les commandes des modules ; leurs relations exactes avec les builds de `core/` et des implants seront précisées dans leurs inventaires | [`TeamServerRuntimeConfig.cpp`](../teamServer/teamServer/TeamServerRuntimeConfig.cpp), [`docs/artifacts.md`](artifacts.md) |
| Certificats et clés | Fichiers de runtime | TLS gRPC ; certificats du listener HTTPS | [`TeamServerBootstrap.cpp`](../teamServer/teamServer/TeamServerBootstrap.cpp), [`certs/CMakeLists.txt`](../certs/CMakeLists.txt) |

## Fonctionnalités présentes

Les identifiants ci-dessous serviront à suivre les audits ultérieurs. Ils désignent des fonctions observées dans le code, sans conclure qu'elles sont opérationnelles dans toutes les configurations.

| ID | Fonctionnalité | Surface et composants principaux |
| --- | --- | --- |
| TS-01 | Démarrage, lecture de configuration, journalisation et serveur gRPC TLS | `main.cpp`, `TeamServerBootstrap.cpp`, `TeamServerRuntimeConfig.cpp` |
| TS-02 | Authentification des opérateurs et contrôle des appels gRPC | `Authenticate`, `TeamServerAuth.cpp`, `ensureAuthenticated` |
| TS-03 | Création, liste et arrêt des listeners primaires HTTP, HTTPS, TCP, GitHub et DNS | `ListListeners`, `AddListener`, `StopListener`, `TeamServerListenerSessionService.cpp`, `core/listener/` |
| TS-04 | Liste et arrêt des sessions ; suivi des sessions et listeners hébergés par les beacons | `ListSessions`, `StopSession`, `TeamServerListenerSessionService.cpp` |
| TS-05 | Préparation, mise en file et collecte des résultats des commandes de session | `TeamServerCommandPreparationService.cpp`, `TeamServerListenerSessionService.cpp`, `core/listener/Listener.cpp` |
| TS-06 | Jobs durables : opérations `echo` et `session_command`, état, consultation, liste et flux d'événements | `SubmitJob`, `GetJobExecution`, `ListJobExecutions`, `SubscribeJobEvents`, `JobApplicationService.cpp`, `SqliteJobRepository.cpp` |
| TS-07 | Catalogue des commandes, aide, état des modules chargés, suivi des chargements et rechargement des modules `.so` | `ListCommands`, `GetCommandHelp`, `ListModules`, `TeamServerCommandCatalogService.cpp`, `TeamServerHelpService.cpp`, `TeamServerModuleLoader.cpp` |
| TS-08 | Préparateurs spécialisés de commandes | `AssemblyExec`, `Chisel`, transfert de fichiers, `Script`, `MiniDump`, `Inject` et préparateur d'artefacts de modules (`ScreenShot`, `KerberosUseTicket`, `PsExec`, `CoffLoader`, `DotnetExec`, `PwSh`) dans `teamServer/teamServer/TeamServer*CommandPreparer.cpp` |
| TS-09 | Catalogue d'artefacts, téléversement, téléchargement, suppression des artefacts générés et hébergement de fichiers via listener | `ListArtifacts`, `DownloadArtifact`, `UploadArtifact`, `DeleteGeneratedArtifact`, `TeamServerArtifactService.cpp`, `TeamServerArtifactCatalog.cpp`, `TeamServerLocalOperationService.cpp` |
| TS-10 | Coffre d'identifiants : liste, lecture, ajout, modification, suppression, chiffrement sur disque et références `--vault` dans certaines commandes | API `Credential*`, `TeamServerCredentialVaultService.cpp`, `TeamServerCommandPreparationService.cpp` |
| TS-11 | Proxy SOCKS : démarrage, arrêt, liaison et déliaison à une session | `ControlSocks`, `TeamServerSocksService.cpp`, `libs/libSocks5/` |
| TS-12 | Opérations typées : informations et binaire d’un listener, dépôt de fichiers, installation d’outils, hébergement et rechargement des modules | `GetListenerInfo`, `GetBeaconBinary`, `UploadListenerFile`, `InstallTool`, `InstallToolBundle`, `HostArtifact`, `ReloadModules`, `TeamServerListenerArtifactService.cpp`, `TeamServerLocalOperationService.cpp` |
| TS-13 | Traitement postérieur des résultats : suivi des modules, erreurs des commandes et artefacts issus des réponses | `TeamServerListenerSessionService::handleCmdResponse`, `TeamServerFileArtifactService.cpp` |
| TS-14 | Génération et stockage de charges brutes ou Donut pour certains préparateurs de commandes | `TeamServerShellcodeService.cpp`, `TeamServerGeneratedArtifactStore.cpp`, `thirdParty/donut/` |

### Détail des commandes préparées par le TeamServer (TS-08)

| Préparateur | Commandes reconnues | Source |
| --- | --- | --- |
| AssemblyExec | `assemblyexec` | [`TeamServerAssemblyExecCommandPreparer.cpp`](../teamServer/teamServer/TeamServerAssemblyExecCommandPreparer.cpp) |
| Inject | `inject` | [`TeamServerInjectCommandPreparer.cpp`](../teamServer/teamServer/TeamServerInjectCommandPreparer.cpp) |
| Chisel | `chisel` | [`TeamServerChiselCommandPreparer.cpp`](../teamServer/teamServer/TeamServerChiselCommandPreparer.cpp) |
| Transfert de fichiers | `download`, `upload` | [`TeamServerFileTransferCommandPreparer.cpp`](../teamServer/teamServer/TeamServerFileTransferCommandPreparer.cpp) |
| Scripts | `script`, `powershell` | [`TeamServerScriptCommandPreparer.cpp`](../teamServer/teamServer/TeamServerScriptCommandPreparer.cpp) |
| MiniDump | `minidump` | [`TeamServerMiniDumpCommandPreparer.cpp`](../teamServer/teamServer/TeamServerMiniDumpCommandPreparer.cpp) |
| Artefacts de modules | `screenshot`, `kerberosuseticket`, `psexec`, `coffloader`, `dotnetexec`, `pwsh` | [`TeamServerModuleArtifactCommandPreparer.cpp`](../teamServer/teamServer/TeamServerModuleArtifactCommandPreparer.cpp) |

Le TeamServer prépare également les commandes communes et les commandes des modules `.so` chargés ; voir l'[inventaire de `core/`](core-inventory.md) pour leur catalogue.

### Surface des opérations (TS-11 et TS-12)

Le client appelle les méthodes typées de `TeamServerOperations`. Le protocole gRPC
expose 31 RPC, dont les opérations SOCKS, listener, outils et artefacts ; il
n'expose plus d'exécution de commande terminal en texte. Voir
[`TeamServerApi.proto`](../protocol/TeamServerApi.proto).

### Limite avec le sous-module `core/`

Le build racine ajoute 45 dossiers de modules de `core/`, répartis dans son CMake sous « Exploit » (24), « Enum » (12) et « Pivot » (9). Les commandes et comportements propres à chaque module relèvent de l'inventaire de `C2Core` ; pour le TeamServer, l'élément à suivre est leur compilation, chargement, catalogue, préparation et restitution des résultats. Source : [`core/modules/CMakeLists.txt`](../core/modules/CMakeLists.txt).

## À compléter avant l'audit

- Utiliser les identifiants `TS-01` à `TS-14` pour examiner chaque fonctionnalité après validation de cet inventaire.
