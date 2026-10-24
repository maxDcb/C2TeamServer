# Inventaire du client Python

État du dépôt : `codex/dev-general` à `3d7a6e6` (24 octobre 2026).

Les versions ci-dessous décrivent ce commit avant [la mise à jour des dépendances externes](external-dependency-updates.md), qui porte le minimum à Python 3.12 et remplace `pyqtdarktheme` par `qt-material`.

Cet inventaire décrit les composants, dépendances et fonctions présents dans `C2Client/`. Il ne conclut pas encore sur leur qualité ni sur leur bon fonctionnement. Voir aussi les inventaires de [`core/`](core-inventory.md), de l'[implant Windows](c2implant-windows-inventory.md) et de l'[implant Linux](c2implant-linux-inventory.md).

## Périmètre et points d'entrée

| Élément | Rôle | Source |
| --- | --- | --- |
| Paquet Python `C2Client` | Application opérateur, compatible Python 3.11 ou plus | [`pyproject.toml`](../C2Client/pyproject.toml) |
| `c2client` | Démarrage de l'interface Qt, connexion au TeamServer et fenêtre de connexion | [`GUI.py`](../C2Client/C2Client/GUI.py) |
| `c2jobs` | CLI de soumission, consultation et suivi des jobs durables | [`jobs_cli.py`](../C2Client/C2Client/jobs_cli.py) |
| API gRPC | Contrat partagé avec le TeamServer, stubs Python générés au build puis localisés au lancement | [`TeamServerApi.proto`](../protocol/TeamServerApi.proto), [`protocol_bindings.py`](../C2Client/C2Client/protocol_bindings.py), [`grpcClient.py`](../C2Client/C2Client/grpcClient.py) |
| Configuration | Variables d'environnement et fichier `.env` local | [`env.py`](../C2Client/C2Client/env.py), [`.env.example`](../C2Client/.env.example) |

## Dépendances Python déclarées

Les versions et sources suivantes sont déclarées dans [`pyproject.toml`](../C2Client/pyproject.toml). [`requirements.txt`](../C2Client/requirements.txt) décrit aussi une installation par `pip` ; les deux fichiers ne remplissent pas exactement le même rôle.

| Dépendance | Déclaration | Usage observé dans le client |
| --- | --- | --- |
| PyQt6 | `6.7.0` | Fenêtre, panneaux, signaux, threads et composants graphiques |
| pyqtdarktheme | Sans version épinglée | Thème de l'interface |
| grpcio | `1.78.0` | Canal TLS et appels TeamServer |
| protobuf | `6.33.5` | Messages et stubs générés depuis le `.proto` |
| gitpython | `3.1.61` | Clonage des dépôts de modules locaux depuis les fichiers `.conf` |
| requests | `2.33.0` | Accès aux releases GitHub de Batcave |
| donut-shellcode | [fork `maxDcb/donut`](https://github.com/maxDcb/donut), branche `master` | Génération locale de shellcode pour `dropper` |
| agent-core | [dépôt `maxDcb/agent-core`](https://github.com/maxDcb/agent-core), commit `dfa341b` | Orchestration, sessions, outils et fournisseurs de l'assistant ; maintenu par toi |
| openai | `3.36.1` | Fournisseur de modèle via `agent-core` |
| markdown | Sans version épinglée | Rendu des réponses dans le panneau assistant |
| PyYAML | `>=6,<7` | Lecture des métadonnées des skills de l'assistant |
| setuptools | Sans version épinglée | Installation, ressources du paquet et build Python ; `wheel` est requis pour le build |
| pycryptodome, pwn, pefile | `3.23.0`, `1.0`, `2024.8.26` | Pas d'import direct dans le client ; utilisés par les dépôts de modules configurés : [correspondance détaillée](remaining-dependencies-inventory.md) |

Les dépendances de test sont `pytest==9.0.3` et `pytest-qt==4.5.0` dans l'extra `test`. Le build du protocole et le packaging peuvent nécessiter l'outillage Python/gRPC décrit dans [`docs/build.md`](build.md) et [`docs/release.md`](release.md).

## Modules Git et sources externes

`C2Client/` ne contient pas de sous-module Git déclaré dans [`.gitmodules`](../.gitmodules). Ses intégrations Git externes passent par les dépendances `pip` ou par les dépôts configurés ci-dessous.

| Source | Mode d'intégration | Relation au client |
| --- | --- | --- |
| `agent-core` | Dépendance `pip` depuis un commit Git ; maintenu par toi | Moteur de l'assistant et des tâches |
| `donut-shellcode` | Dépendance `pip` depuis la branche `master` du fork maintenu par toi | Génération locale des charges utilisées par `dropper` |
| Six dépôts de droppers | URLs dans [`DropperModules.conf`](../C2Client/C2Client/DropperModules.conf) ; tu maintiens les cinq dépôts `maxDcb` et seulement l'intégration et la version utilisée de `almounah/GoDroplets` | `PeDropper`, `PowershellWebDelivery`, `PeInjectorSyscall`, `GoDroplets`, `ElfDropper`, `EarlyCascade` ; clonés et importés par le terminal |
| Un dépôt de module shellcode | URL dans [`ShellCodeModules.conf`](../C2Client/C2Client/ShellCodeModules.conf) ; maintenu par toi | `DreamWalkers` ; cloné et importé par le terminal |
| Batcave | [releases GitHub](https://github.com/exploration-batcave/batcave) | Recherche et récupération de gadgets ou bundles depuis le terminal |
| TeamServer | Connexion gRPC TLS | Listeners, sessions, commandes, jobs, artefacts, identifiants et catalogue de modules |
| OpenAI ou endpoint Azure OpenAI | Service externe choisi par la configuration de l'assistant | Conversations et tâches assistées |

Les statuts de maintenance d'`agent-core` et des sept dépôts de modules configurés ci-dessus ont été confirmés par le propriétaire du projet.

## Fonctionnalités présentes

Les identifiants `CL-01` à `CL-17` serviront à suivre les audits ultérieurs. Ils désignent des fonctions présentes dans le code, sans présumer de leur fonctionnement dans toutes les configurations.

| ID | Fonctionnalité | Surface et composants principaux |
| --- | --- | --- |
| CL-01 | Démarrage de l'application, chargement de `.env`, thème, connexion et état de l'API | `GUI.py`, `env.py`, `ui_status.py`, `panel_style.py` |
| CL-02 | Canal gRPC TLS, authentification, métadonnées, statut des RPC et chargement des stubs générés | `grpcClient.py`, `protocol_bindings.py`, `grpc_status.py` |
| CL-03 | Liste, création et arrêt des listeners | `ListenerPanel.py` |
| CL-04 | Liste, interaction et arrêt des sessions ; état et actualisation | `SessionPanel.py` |
| CL-05 | Vue graphique des listeners et sessions, relations et rafraîchissement | `GraphPanel.py` |
| CL-06 | Consoles de session, envoi de commandes via jobs, affichage des résultats, historique et aide | `ConsolePanel.py`, `command_event_hub.py` |
| CL-07 | Catalogue des commandes, détails et filtres | `CommandPanel.py` |
| CL-08 | Autocomplétion des commandes et paramètres, y compris sélections d'artefacts et d'identifiants | `autocomplete.py`, `ConsolePanel.py`, `TerminalPanel.py` |
| CL-09 | Catalogue, filtres, téléversement, téléchargement et suppression d'artefacts autorisés | `ArtifactPanel.py` |
| CL-10 | Coffre d'identifiants : consultation, révélation, ajout, modification et suppression | `CredentialVaultPanel.py` |
| CL-11 | Terminal local : aide, commandes TeamServer, hébergement d'artefacts, SOCKS et rechargement des modules | `TerminalPanel.py` |
| CL-12 | Intégration Batcave : recherche, installation et transfert d'outils | `TerminalPanel.py`, `TerminalModules/Batcave/batcave.py` |
| CL-13 | Génération locale de droppers et de shellcode avec modules Git configurés et Donut | `TerminalPanel.py`, `DropperModules.conf`, `ShellCodeModules.conf` |
| CL-14 | Hooks Python activables, déclenchés par événements client, listener, session et console | `ScriptPanel.py`, `Scripts/` |
| CL-15 | Assistant conversationnel, contexte de session, outils dérivés du catalogue des commandes et suivi des résultats | `AssistantPanel.py`, `assistant_agent/domain/`, `assistant_agent/tools/` |
| CL-16 | Tâches/skills de l'assistant : catalogue, lancement, progression, reprise et stockage des exécutions | `assistant_agent/skills/`, `assistant_agent/storage/` |
| CL-17 | CLI des jobs : `submit`, `get`, `list`, `watch` avec curseur et filtres d'événements | `jobs_cli.py` |

### Surface de l'interface

La fenêtre principale affiche les sessions et listeners dans l'onglet `Main`, ainsi qu'un onglet `Graph`. La zone inférieure contient `Terminal`, `Hooks`, `Artifacts`, `Credentials`, `Commands` et `Data AI`, auxquels s'ajoutent les consoles des sessions ouvertes. `Data AI` contient les vues `Conversation` et `Tasks`. Sources : [`GUI.py`](../C2Client/C2Client/GUI.py), [`ConsolePanel.py`](../C2Client/C2Client/ConsolePanel.py), [`AssistantPanel.py`](../C2Client/C2Client/AssistantPanel.py).

### Jobs et commandes

`GrpcClient.sendSessionCommand` soumet une opération `session_command` à l'API des jobs durables ; `streamSessionCommandResults` lit les événements et reconstruit les résultats pour les consoles. Le client expose aussi les autres RPC du contrat : authentification, listeners, sessions, artefacts, identifiants, commandes/modules, aide et terminal. Sources : [`grpcClient.py`](../C2Client/C2Client/grpcClient.py), [`TeamServerApi.proto`](../protocol/TeamServerApi.proto).

### Hooks et assistant

Les hooks de `ScriptPanel.py` couvrent `ManualStart`, `OnStart`, `OnStop`, les démarrages/arrêts de listeners et sessions, les mises à jour de session et les envois/réceptions de console. Trois hooks suivis dans [`C2Client/C2Client/Scripts/`](../C2Client/C2Client/Scripts/checkSandbox.py) font partie du produit et servent aussi d'exemples : `checkSandbox`, `startListenerHttp8443` et `loadCommonModules`. `template.py.example` est un modèle non chargé comme hook.

L'assistant utilise `agent-core` et des outils liés au TeamServer : aide des commandes, modules chargés, sessions vivantes et outils construits depuis le catalogue des commandes. Deux skills figurent dans le catalogue local : `inventory_local` et `identify-user`. Sources : [`registry.py`](../C2Client/C2Client/assistant_agent/tools/registry.py), [`catalog.py`](../C2Client/C2Client/assistant_agent/skills/catalog.py).

## À compléter avant l'audit

- Examiner séparément la provenance et les variantes des modules C++ produits par `core/` pour le TeamServer et les implants.
