# Inventaire de C2Core

Source : sous-module [`core/`](../core/README.md) de `C2TeamServer`, au commit `331f441` sur `codex/dev-general` (24 octobre 2026). Le dépôt `C2Core` est maintenu par le propriétaire du projet. Cet inventaire relève les composants et les commandes déclarés ; il ne constitue pas un audit de comportement.

## Place dans l'ensemble

`C2Core` est un dépôt source partagé sans build racine autonome. Chaque parent le compile avec ses propres dépendances, options et sorties. Les commits épinglés relevés sont différents : TeamServer `331f441`, C2Implant Windows `108a370` et C2LinuxImplant `2b6dbe4`. Les 45 modules ci-dessous sont relevés au commit du TeamServer ; les écarts entre versions seront examinés pendant les audits.

| Dossier | Contenu et rôle | Source |
| --- | --- | --- |
| `modules/ModuleCmd/` | `C2Message`, format des messages, interface `ModuleCmd`, commandes communes, utilitaires et spécifications de commande | [`ModuleCmd.hpp`](../core/modules/ModuleCmd/ModuleCmd.hpp), [`C2Message.hpp`](../core/modules/ModuleCmd/C2Message.hpp), [`CommandSpecs/common/`](../core/modules/ModuleCmd/CommandSpecs/common/end.json) |
| `listener/` | Sessions, file de tâches/résultats, framing TCP et listeners HTTP, TCP, DNS, GitHub et SMB | [`Listener.hpp`](../core/listener/Listener.hpp), [`Session.hpp`](../core/listener/Session.hpp), [`TcpFrameBuffer.hpp`](../core/TcpFrameBuffer.hpp) |
| `beacon/` | Boucle de check-in, routage des tâches et résultats, chargement de modules, pivot et transports du beacon | [`Beacon.hpp`](../core/beacon/Beacon.hpp), [`Beacon.cpp`](../core/beacon/Beacon.cpp), [`CMakeLists.txt`](../core/beacon/CMakeLists.txt) |
| `modules/` | 45 modules compilés par les projets parents ; un manifeste JSON par module | [`CMakeLists.txt`](../core/modules/CMakeLists.txt) |
| `modules/ModuleTemplate/` | Modèle de développement non ajouté aux 45 cibles du CMake | [`ModuleTemplate/`](../core/modules/ModuleTemplate/CMakeLists.txt) |

`C2Core` ne déclare pas de sous-modules Git propres. Les dépendances sont fournies par les projets parents.

## Dépendances fournies par les parents

| Élément | Usage dans `core/` | Provenance dans les parents |
| --- | --- | --- |
| nlohmann/json, cpp-base64 | Messages, configuration et encodage | Conan et cible `c2_base64` des parents |
| `SocketHandler`, `Dnscommunication`, `PipeHandler`, `SocksServer`, `MemoryModule` | Transports TCP, DNS, SMB, SOCKS et chargement de modules | Sous-modules ou implémentations dummy selon le parent |
| cpp-httplib, OpenSSL | Transports HTTP/GitHub côté Linux et listeners côté TeamServer | Dépendances du parent Linux et du TeamServer |
| WinHTTP et API Windows | Transports et modules côté Windows | Windows SDK et bibliothèques système |
| libssh2 | Module `SshExec` | Conan des trois parents |
| Donut, COFFLoader, COFFPacker | Modules qui génèrent ou exécutent les formats correspondants, et tests | Sous-modules du parent Windows ou services du TeamServer selon le chemin |
| spdlog | Journalisation de listeners côté TeamServer | Dépendance Conan du TeamServer |
| bibliothèques Windows (`Advapi32`, `Wtsapi32`, `Taskschd`, `WsmSvc`, `GdiPlus`, COM) et Linux (`smbclient`, `dl`) | Liens conditionnels de modules et transports | SDK/paquets système des plateformes |

Sources : [`beacon/CMakeLists.txt`](../core/beacon/CMakeLists.txt), [`modules/CMakeLists.txt`](../core/modules/CMakeLists.txt), [`AGENT.md`](../core/AGENT.md), [`conanfile.txt`](../conanfile.txt), [inventaire Windows](c2implant-windows-inventory.md), [inventaire Linux](c2implant-linux-inventory.md).

## Fonctions partagées hors modules

| ID | Fonctionnalité | Source |
| --- | --- | --- |
| CORE-01 | Format `C2Message` et bundle de session, sérialisation JSON/base64 et champs de résultat | [`C2Message.hpp`](../core/modules/ModuleCmd/C2Message.hpp) |
| CORE-02 | Contrat `ModuleCmd` : préparation côté TeamServer, traitement côté implant, réponses, erreurs et exécution récurrente | [`ModuleCmd.hpp`](../core/modules/ModuleCmd/ModuleCmd.hpp) |
| CORE-03 | Commandes communes `end`, `help`, `listener`, `listModule`, `loadModule`, `sleep`, `unloadModule` | [`CommandSpecs/common/`](../core/modules/ModuleCmd/CommandSpecs/common/end.json), [`CommonCommand.hpp`](../core/modules/ModuleCmd/CommonCommand.hpp) |
| CORE-04 | Listeners HTTP, TCP, DNS, GitHub et SMB ; sessions et files de tâches/résultats | [`listener/`](../core/listener/Listener.hpp) |
| CORE-05 | Beacons HTTP/HTTPS, TCP, DNS, GitHub et SMB avec boucle de check-in | [`beacon/`](../core/beacon/Beacon.hpp) |
| CORE-06 | Chargement/déchargement de modules implant, routage vers sessions enfants, listeners enfants TCP/SMB et tunnel SOCKS | [`Beacon.cpp`](../core/beacon/Beacon.cpp) |
| CORE-07 | Variantes Windows/Linux dans les transports et liens conditionnels du build | [`beacon/CMakeLists.txt`](../core/beacon/CMakeLists.txt), [`BeaconHttp.cpp`](../core/beacon/BeaconHttp.cpp), [`BeaconGithub.cpp`](../core/beacon/BeaconGithub.cpp) |

La présence de code SMB dans `core/` ne signifie pas que le parent Linux possède un transport SMB : il lie un [`PipeHandler` dummy](https://github.com/maxDcb/C2LinuxImplant/blob/17bfe61/libs/libPipeHandlerDumy/src/PipeHandler.cpp). Le transport SMB opérationnel est destiné à Windows.

## Catalogue des 45 modules

La colonne « plateformes » vient des manifestes JSON au commit `331f441`. Elle décrit la cible annoncée par le catalogue, pas une validation runtime. Les identifiants `M01` à `M45` suivent l'ordre de [`modules/CMakeLists.txt`](../core/modules/CMakeLists.txt).

| ID | Module | Plateformes | Fonction annoncée |
| --- | --- | --- | --- |
| M01 | `AssemblyExec` | Windows | Exécution de shellcode préparé |
| M02 | `Chisel` | Windows | Lancement de Chisel préparé par le TeamServer |
| M03 | `CoffLoader` | Windows | Chargement et exécution de COFF/BOF |
| M04 | `Download` | Windows, Linux | Récupération de fichier depuis le beacon |
| M05 | `Evasion` | Windows | Action d'évasion |
| M06 | `Inject` | Windows | Injection de shellcode préparé |
| M07 | `KerberosUseTicket` | Windows | Import d'un ticket Kerberos |
| M08 | `MakeToken` | Windows | Création d'un contexte de jeton |
| M09 | `Powershell` | Windows | Commandes et scripts PowerShell |
| M10 | `Rev2self` | Windows | Retour au jeton initial |
| M11 | `Run` | Windows, Linux | Exécution d'une commande système |
| M12 | `Script` | Windows, Linux | Exécution d'un script fourni par le TeamServer |
| M13 | `StealToken` | Windows | Emprunt d'un jeton de processus |
| M14 | `Upload` | Windows, Linux | Envoi d'un artefact vers le beacon |
| M15 | `MkDir` | Windows, Linux | Création de répertoire |
| M16 | `Remove` | Windows, Linux | Suppression de fichier ou répertoire |
| M17 | `KillProcess` | Windows, Linux | Arrêt d'un processus |
| M18 | `KeyLogger` | Windows | Capture clavier |
| M19 | `ScreenShot` | Windows | Capture d'écran |
| M20 | `MiniDump` | Windows | Capture et traitement de dump |
| M21 | `DotnetExec` | Windows | Chargement et exécution d'assemblages .NET |
| M22 | `PwSh` | Windows | Runner PowerShell en mémoire |
| M23 | `Shell` | Windows, Linux | Shell persistant |
| M24 | `Registry` | Windows | Opérations sur le registre |
| M25 | `ChangeDirectory` (`cd`) | Windows, Linux | Changement de répertoire |
| M26 | `ListDirectory` (`ls`) | Windows, Linux | Liste de répertoire |
| M27 | `ListProcesses` (`ps`) | Windows, Linux | Liste de processus |
| M28 | `PrintWorkingDirectory` (`pwd`) | Windows, Linux | Répertoire courant |
| M29 | `Cat` | Windows, Linux | Lecture de fichier |
| M30 | `Tree` | Windows, Linux | Arborescence de répertoire |
| M31 | `GetEnv` | Windows, Linux | Variables d'environnement |
| M32 | `Whoami` | Windows, Linux | Identité et groupes courants |
| M33 | `Netstat` | Windows, Linux | Connexions réseau |
| M34 | `IpConfig` | Windows, Linux | Interfaces réseau |
| M35 | `EnumerateShares` | Windows, Linux | Partages SMB visibles |
| M36 | `EnumerateRdpSessions` | Windows | Sessions RDP |
| M37 | `SpawnAs` | Windows | Processus avec identifiants fournis |
| M38 | `PsExec` | Windows | Exécution distante via service |
| M39 | `ReversePortForward` | Windows, Linux | Redirection de port inverse |
| M40 | `WmiExec` | Windows | Exécution distante WMI |
| M41 | `TaskScheduler` | Windows | Tâches planifiées |
| M42 | `WinRM` | Windows | Exécution distante WinRM |
| M43 | `DcomExec` | Windows | Exécution distante DCOM |
| M44 | `CimExec` | Windows | Exécution distante CIM/WMI |
| M45 | `SshExec` | Windows, Linux | Exécution distante SSH |

Les manifestes indiquent 24 modules Windows uniquement et 21 modules Windows/Linux. Les sept commandes communes sont cataloguées séparément sous `CORE-03`. Les chemins détaillés, arguments et filtres d'artefacts figurent dans les manifestes JSON de chaque dossier sous [`modules/`](../core/modules/CMakeLists.txt).

## Frontières pour les audits

- Comparer les trois commits de `core/` épinglés par TeamServer, Windows et Linux avant de généraliser une observation.
- Vérifier chaque module dans sa plateforme déclarée et distinguer préparation côté TeamServer et exécution côté implant.
- Cataloguer séparément les comportements internes des dépendances maintenues par toi (`libDns`, `libSocketHandler`, `libSocks5`, `libPipeHandler`, `COFFPacker`, forks Donut, MemoryModule et COFFLoader) au moment de leur audit.
