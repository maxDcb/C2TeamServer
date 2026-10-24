# Complément d'inventaire des dépendances

État au 24 octobre 2026. Ce complément recense les dépendances qui dépassent les seuls manifestes directs des cinq [inventaires principaux](inventory-index.md). Les versions et rôles proviennent des manifestes et scripts suivis dans les dépôts ; les réponses sur la maintenance viennent du propriétaire. Il ne mesure pas encore l'usage réel de chaque bibliothèque transitive.

## Sous-module imbriqué et services externes

| Élément | Source | Statut et relation |
| --- | --- | --- |
| `Binject/go-donut` à `fcdcc35` | [`.gitmodules` de Donut](../thirdParty/donut/.gitmodules), arbre Git du sous-module `donut` | Sous-module imbriqué de ton fork Donut ; dépendance tierce inchangée, non maintenue par toi |
| `exploration-batcave/batcave` | [`batcave.py`](../C2Client/C2Client/TerminalModules/Batcave/batcave.py) | Releases consommées par le client ; service tiers lié au projet, sans maintenance directe de ta part |
| `almounah/GoDroplets` | [`DropperModules.conf`](../C2Client/C2Client/DropperModules.conf) | Dépôt externe ; tu maintiens son intégration et la version utilisée par le client, pas le dépôt lui-même |
| `UnmanagedPowerShell` | [README de C2Implant](https://github.com/maxDcb/C2Implant/blob/8a0137a/README.md) | Cité uniquement dans le README du parent Windows ; aucun sous-module ni lien de build relevé. Référence documentaire à confirmer, pas une dépendance déclarée du build |

Le sous-module `go-donut` possède un [`go.mod`](../thirdParty/donut/generators/go-donut/go.mod) qui déclare Go 1.16 et trois dépendances : `github.com/Binject/debug`, `github.com/akamensky/argparse` et `github.com/google/uuid`. Cela décrit le générateur Go imbriqué, sans prouver qu'il est compilé par les parents C++.

Le fork Donut embarque aussi des archives aPLib (`aplib32/64.a` et `.lib`) et un en-tête dans [`thirdParty/donut/lib/`](../thirdParty/donut/lib/aplib64.a) ; son [Makefile](../thirdParty/donut/Makefile) lie `aplib64.a`. Il s'agit d'une dépendance vendored, distincte du sous-module `go-donut`.

## Graphe verrouillé du TeamServer

[`conanfile.txt`](../conanfile.txt) déclare 7 paquets directs. [`conan.lock`](../conan.lock) en énumère 14 sous `requires` : les 7 directs, plus les 7 références ci-dessous. La présence dans le lock ne suffit pas à attribuer un usage direct au TeamServer.

| Référence additionnelle du lock | Version verrouillée | Autre déclaration locale |
| --- | --- | --- |
| zlib | 1.3.1 | `find_package(ZLIB)` dans le [CMake racine](../CMakeLists.txt) |
| fmt | 12.1.0 | Aucune dans `conanfile.txt` |
| re2 | 20251105 | Aucune dans `conanfile.txt` |
| crowcpp-crow | 1.3.0 | Aucune dans `conanfile.txt` |
| c-ares | 1.34.6 | Aucune dans `conanfile.txt` |
| asio | 1.29.0 | Aucune dans `conanfile.txt` |
| abseil | 20250127.0 | Aucune dans `conanfile.txt` |

Le même lock énumère 4 `build_requires` : CMake 3.31.10, protobuf 6.33.5, zlib 1.3.1 et abseil 20250127.0. Les dépendances Python transitives ne sont pas verrouillées par un fichier équivalent dans `C2Client/` ; les déclarations directes sont dans [`pyproject.toml`](../C2Client/pyproject.toml) et [`requirements.txt`](../C2Client/requirements.txt).

Les dépôts C2Implant Windows (`8a0137a`) et C2LinuxImplant (`17bfe61`) déclarent Conan dans `conanfile.txt`, mais aucun `conan.lock` n'est suivi à ces commits. Leurs graphes transitifs exacts dépendront donc de la résolution Conan retenue pour chaque build.

## Outils et paquets système du build TeamServer

Les workflows [CI](../.github/workflows/Tests.yml) et [release](../.github/workflows/Release.yml) installent sous Ubuntu 22.04 : `golang-cfssl`, `libegl1`, `libgl1`, `libsmbclient-dev`, `libxkbcommon-x11-0`, `libxcb-cursor0`, `libxcb-icccm4`, `libxcb-image0`, `libxcb-keysyms1`, `libxcb-render-util0` et `libxcb-xinerama0`. Ils installent aussi Conan 2.24.0 et Python 3.12 via `actions/setup-python@v5`. Le build emploie CMake, un compilateur C/C++, `protoc` et les plugins gRPC. SQLite 3, `pthread`, `dl` et `rt` sont liés depuis le système ; voir l'[inventaire TeamServer](teamserver-inventory.md).

Les workflows utilisent `actions/checkout@v4`, `actions/cache@v4`, `actions/upload-artifact@v4`, `actions/download-artifact@v4` et `svenstaro/upload-release-action@v2` pour la CI et la publication. Les [scripts de packaging](../packaging/import_implant_releases.py) consomment l'API et les releases GitHub des deux implants.

## Références externes fixes ou flottantes

| Source | Référence utilisée par le projet |
| --- | --- |
| `agent-core` Python | Commit complet `dfa341b06850600192172a6ffcc422ed022ad244` dans les deux manifestes du client |
| `donut-shellcode` Python | Branche `master` du fork, sans commit figé dans les deux manifestes |
| Sept dépôts de modules client | URLs seules dans les fichiers `.conf` ; aucun commit ou tag épinglé dans ces fichiers |
| Batcave | Release GitHub `latest` recherchée à l'exécution |
| Releases des implants importées par le packaging | Tag configurable ; `latest` par défaut pour chaque dépôt |
| Sous-modules Git C++ | Commits figés par les arbres Git des parents, y compris `go-donut` dans le fork Donut |

Cette table décrit la reproductibilité des références déclarées ; elle ne juge pas encore la stratégie de mise à jour.

## Déclarations Python à attribuer

Le client déclare `pycryptodome==3.23.0`, `pwn==1.0` et `pefile==2024.8.26` sans import direct dans ses propres sources. Les dépôts publics configurés par le client montrent leurs consommateurs :

| Paquet du client | Import relevé dans un module externe configuré |
| --- | --- |
| `pycryptodome` (`Crypto`) | [`PeDropper.py`](https://github.com/maxDcb/PeDropper/blob/66c3d1e/PeDropper.py), [`ElfDropper.py`](https://github.com/maxDcb/ElfDropper/blob/cabd2a7/ElfDropper.py), [`GoDroplets.py`](https://github.com/almounah/GoDroplets/blob/9328682/GoDroplets.py) |
| `pefile` | [`PeInjectorSyscall.py`](https://github.com/maxDcb/PeInjectorSyscall/blob/1647e36/PeInjectorSyscall.py) |
| `pwn` | [`ElfDropper/elfToShellcode/elfToShellcode.py`](https://github.com/maxDcb/ElfDropper/blob/cabd2a7/elfToShellcode/elfToShellcode.py) ; la distribution `pwn==1.0` déclarée dans le client est distincte de la distribution actuelle `pwntools`, qui documente également `from pwn import *` ([PyPI](https://pypi.org/project/pwntools/)). Leur équivalence effective reste à tester. |

`PyYAML>=6,<7` est déclaré dans `pyproject.toml` et importé par les skills de l'assistant ; il manque dans `requirements.txt`. `setuptools` figure dans `pyproject.toml` et son système de build avec `wheel`, mais pas dans `requirements.txt`. Les paquets de tests `pytest` et `pytest-qt` se trouvent dans `requirements.txt` et l'option `test` du projet.

## Dépendances des dépôts de modules configurés

Les sept dépôts de [`DropperModules.conf`](../C2Client/C2Client/DropperModules.conf) et [`ShellCodeModules.conf`](../C2Client/C2Client/ShellCodeModules.conf) ont été consultés à leurs têtes publiques le 24 octobre 2026. Les commits observés sont : `PeDropper` `66c3d1e`, `PowershellWebDelivery` `2370147`, `PeInjectorSyscall` `1647e36`, `GoDroplets` `9328682`, `ElfDropper` `cabd2a7`, `EarlyCascade` `9ce8fc1` et `DreamWalkers` `a798b85`. Les imports Python non cités ci-dessus sont ceux de la bibliothèque standard dans les points d'entrée examinés.

| Dépôt | Autres dépendances de build ou livrées dans le dépôt |
| --- | --- |
| [GoDroplets](https://github.com/almounah/GoDroplets/tree/9328682) | [`go.mod`](https://github.com/almounah/GoDroplets/blob/9328682/go.mod) : Go 1.23.1 et `golang.org/x/sys` 0.27.0 ; README : MinGW pour la cible DLL |
| [ElfDropper](https://github.com/maxDcb/ElfDropper/tree/cabd2a7) | `g++`, `strip`, `pthread` ; sources vendored de cpp-httplib 0.18.5, en-têtes OpenSSL 3.3.1 et archives statiques `libssl.a`, `libcrypto.a`, `libz.a` dans `lib/` ; provenance des trois archives à vérifier selon le propriétaire ; voir [`compile.sh`](https://github.com/maxDcb/ElfDropper/blob/cabd2a7/compile.sh) |
| [PeDropper](https://github.com/maxDcb/PeDropper/tree/66c3d1e), [PeInjectorSyscall](https://github.com/maxDcb/PeInjectorSyscall/tree/1647e36), [EarlyCascade](https://github.com/maxDcb/EarlyCascade/tree/9ce8fc1) | Compilateurs et bibliothèques système Windows via leurs scripts `compile.bat` |
| [DreamWalkers](https://github.com/maxDcb/DreamWalkers/tree/a798b85) | Compilateur Windows et SDK/.NET pour sa partie `dotnetLoader`, d'après les scripts `compile.bat` |
| [PowershellWebDelivery](https://github.com/maxDcb/PowershellWebDelivery/tree/2370147) | Imports Python standard dans le point d'entrée examiné ; dépend du runtime PowerShell pour le résultat produit |

## Dépendances des autres dépôts maintenus ou forkés

La version `dfa341b` d'[`agent-core`](https://github.com/maxDcb/agent-core/blob/dfa341b/pyproject.toml), épinglée par le client, déclare huit dépendances directes : `anthropic`, `jsonschema[format]`, `langchain-core`, `langchain-openai`, `langgraph`, `langsmith`, `openai` et `requests`. Ses dépendances optionnelles `dev` (`build`, `hypothesis`, `pytest`, `pytest-cov`, `mypy`, `ruff`, `types-jsonschema`) ne sont pas exigées par l'installation normale du client. Le client déclare déjà `openai` et `requests` directement ; leurs contraintes doivent se résoudre conjointement lors de l'installation.

Le [`requirements.txt` d'`agent-core`](https://github.com/maxDcb/agent-core/blob/dfa341b/requirements.txt) n'est pas identique à son `pyproject.toml` : `langsmith` y manque, `pytest` y figure et la contrainte `openai>=1.30.0` y est plus large. Le client installe le dépôt comme paquet Git, donc le manifeste `pyproject.toml` est la déclaration du paquet à considérer pour ce chemin.

Les dépôts C++ consultés n'ajoutent pas de gestionnaire de paquets au build parent : [`libDns`](../libs/libDns/CMakeLists.txt) et [`libSocks5`](../libs/libSocks5/CMakeLists.txt) lient `pthread` sous Linux ; [`libSocketHandler`](../libs/libSocketHandler/CMakeLists.txt) recherche `Threads::Threads` ; [`libPipeHandler`](https://github.com/maxDcb/libPipeHandler/blob/187c023/CMakeLists.txt) ne déclare pas de paquet externe. [`COFFPacker`](https://github.com/maxDcb/COFFPacker/blob/05995ee/CMakeLists.txt) compile ses sources `struct` locales. Les builds autonomes de [`MemoryModule`](https://github.com/maxDcb/MemoryModule/blob/1649d0a/CMakeLists.txt) et [`COFFLoader`](https://github.com/maxDcb/COFFLoader/blob/7460a2f/Makefile) citent les toolchains Windows/MSVC ou MinGW ; l'examen de leurs versions exactement épinglées dans l'implant Windows reste à faire avant de conclure sur leurs éventuels écarts.

## Questions ouvertes

- Vérifier si la mention `UnmanagedPowerShell` dans le README Windows doit rester documentée comme référence historique.
- Résoudre l'écart `PyYAML` et `setuptools` entre les deux déclarations Python lors de l'audit des installations.
- Vérifier que `pwn==1.0` satisfait bien les symboles utilisés par `ElfDropper` ; l'import seul ne prouve pas la compatibilité du paquet.
- Retrouver la provenance exacte des archives statiques OpenSSL/zlib vendored par `ElfDropper` ; le propriétaire l'a signalée comme inconnue à ce stade.
- Relever les dépendances transitives Python dans un environnement de référence si une nomenclature complète des paquets installés est souhaitée.
