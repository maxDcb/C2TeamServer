# C2Client Friendly Roadmap

Objectif: rendre le client plus agreable pour un operateur, puis enrichir proprement l'interaction client/TeamServer. Les items sont classes du moins couteux au plus couteux.

## Todo List

| Ordre | Fait | Chantier | Cout | Impact | Notes |
| --- | --- | --- | --- | --- | --- |
| 1 | [x] | Ajouter une barre de statut client | XS | Fort | Fait. Affiche connexion, host, port, utilisateur, mode dev, certificat charge, dernier refresh RPC et derniere erreur gRPC. Client-only. |
| 2 | [x] | Centraliser toutes les configs client dans `.env` | XS | Fort | Fait. Helpers types dans `env.py`, resolution des chemins, branchement certificat, protocol root, logs, refresh intervals, gRPC, UI et assistant. |
| 3 | [x] | Completer `C2Client/.env.example` | XS | Moyen | Fait. Exemple enrichi avec connexion, auth, certificat, protocol root, UI, gRPC, assistant et modules locaux. |
| 4 | [x] | Utiliser `.env` comme defaults CLI | S | Fort | Fait. `C2_IP`, `C2_PORT` et `C2_DEV_MODE` alimentent les defaults CLI, avec arguments CLI prioritaires. |
| 5 | [x] | Rendre les actions principales visibles | S | Fort | Fait. Boutons `Add Listener`, `Interact`, `Stop`, `Copy ID`, `Refresh`; le clic droit reste disponible comme raccourci. |
| 6 | [x] | Ajouter copie rapide des IDs et infos session | S | Moyen | Copie beacon hash, listener hash, host, user, internal IP depuis tables et graph. |
| 7 | [x] | Ameliorer les messages d'erreur et d'etat | S | Fort | Fait. Helper UI commun pour success/error/info, prefixe action, compactage des messages longs, barre RPC, statuts panels et theme sombre harmonises. |
| 8 | [x] | Nettoyer le bruit console/debug | S | Moyen | Fait. Logging par defaut en WARNING, `print()` UI remplaces, erreurs de scripts visibles dans l'onglet Script sans casser l'UI. |
| 9 | [-] | Ajouter filtres, recherche et tri tables | M | Fort | Non retenu pour le moment. Les tables actuelles restent volontairement simples pendant la stabilisation. |
| 10 | [x] | Humaniser l'etat des sessions | M | Fort | Fait. Etat `Alive/Stale/Killed/Unknown`, last seen relatif, seuil `C2_SESSION_STALE_AFTER_MS=30000`, couleurs discretes et OS complet en tooltip. |
| 11 | [x] | Ameliorer la console beacon | M | Fort | Recherche output, clear, export log, pause autoscroll, bouton resend, affichage `queued/done/error` par `command_id`. |
| 12 | [x] | Transformer `ScriptPanel` en vrai panneau d'automations | M | Moyen | Fait. Table scripts/hooks, enable/disable, erreurs par script, compteur d'activations, run manuel et hook `ManualStart(context)` avec snapshots sessions/listeners; subtilites de triggers en tooltip. |
| 13 | [x] | Ameliorer le formulaire listener | M | Moyen | Fait. Validation port/IP/domain/token avant RPC, defaults par type, aide inline, erreurs inline et bouton Add bloque tant que les champs sont invalides. |
| 14 | [-] | Ajouter un panneau details session | M | Fort | Non retenu pour le moment. Les details session resteront dans la table, les tooltips et la console beacon pendant la stabilisation. |
| 15 | [x] | Ameliorer le graph | M | Moyen | Fait. Layout auto qui separe listeners/beacons/pivots, positions manuelles preservees, boutons Auto/Fit/+/- zoom, labels/tooltips, fond sombre et connecteurs recalcules. |
| 16 | [x] | Reduire la taille des artefacts `screenShot` | M | Moyen | Fait cote code. Format unique PNG: le module Windows encode en PNG via GDI+ avant chunking, le TeamServer force `format=png`, ajoute `.png` si l'extension est omise et rejette les autres extensions. Specs, tests et catalogue mis a jour. Validation reelle Windows a refaire pour mesurer le gain exact. |
| 17 | [x] | Remplacer l'autocomplete Terminal `QCompleter` | M | Fort | Fait. `QCompleter` supprime cote client; Terminal, consoles beacon, Hooks et Assistant utilisent `CompletionInput`, une liste integree au layout avec Tab, Shift+Tab, fleches, Enter et clic. Les placeholders dynamiques console (`<pid>`, `<name>`) restent geres proprement. |
| 18 | [x] | Auditer `libSocks5` | M | Fort | Fait. Audit documente dans `docs/socks5-audit.md`; durcissement du handshake IPv4-only, erreurs SOCKS explicites (`0x07`, `0x08`), timeout de handshake, port de reply en network order, logs bruyants retires, flags atomiques et tests protocole auto `TestsSocksServer`. Hostname/IPv6 restent dans l'item 24. |
| 19 | [ ] | Generer des formulaires de commandes depuis les schemas assistant | L | Fort | Utiliser `assistant_agent/tools/schemas/*.json` pour proposer des commandes guidees sans tout taper a la main. |
| 20 | [ ] | Ajouter `GetServerInfo` / `GetCapabilities` au proto | L | Fort | Version serveur, modules charges, features, chemins runtime, limites max message, auth mode. Premier vrai changement client-server. |
| 21 | [x] | Ajouter `ListCommands` / `ListModules` structure | L | Tres fort | Fait. `ListCommands` expose le catalogue serveur, tab UI `Commands`, autocomplete console sans fallback hardcode, specs simples pour modules, `GetCommandHelp` genere l'aide depuis les specs, `ListModules` stream les modules suivis par beacon, `listModule` affiche name/status dans la console, `loadModule` cache les modules actifs et `unloadModule` propose les modules charges. Persistence/historique modules reportes aux items audit/historique. |
| 22 | [ ] | Synchroniser l'assistant avec `CommandSpecs` / `ListCommands` | L | Tres fort | L'assistant n'est probablement plus a jour depuis la migration CommandSpec. Le faire charger le catalogue serveur, `GetCommandHelp`, les arguments/artefacts requis, modules charges et capabilities pour construire ses commandes depuis la meme source que la console, au lieu de schemas ou prompts statiques. |
| 23 | [ ] | Persister `keyLogger` en artefact live | L | Fort | Ecrire chaque `followUp` dans un fichier `GeneratedArtifacts/keylogger/beacon`, nomme avec hostname + timestamp, visible dans `Artifacts` sans action `dump`; mettre a jour le sidecar/hash a chaque append et garder `stop` limite a l'arret du module. |
| 24 | [x] | Supporter les hostnames SOCKS5 cote beacon | L | Tres fort | Fait cote code. `libSocks5` accepte `ATYP=DName`, le TeamServer transporte `host:<hostname>` vers la beacon, la beacon resout/connecte depuis son contexte, IPv4 reste compatible, les echecs d'init renvoient un reply SOCKS type au lieu d'un EOF. Tests auto `TestsSocksServer`; validation live `scripts/socks5_stress_test.py --socks-hostname` a refaire sur beacon. |
| 25 | [ ] | Ajouter `ValidateCommand` / `DryRunCommand` | L | Tres fort | Verifier une commande sans l'envoyer au beacon; retourner erreur, hint, instruction preparee, fichiers requis. |
| 26 | [ ] | Ajouter un modele d'erreurs type dans le proto | L | Fort | `code`, `message`, `hint`, `details`; eviter de parser du texte libre cote client. |
| 27 | [ ] | Ajouter un credential store serveur pour les modules | XL | Tres fort | Store central cote TeamServer avec RPC list/search/add/update/delete, audit et masquage des secrets; ajouter un `credential_filter` aux CommandSpecs pour autocompleter les modules qui prennent des credentials (`psExec`, `wmiExec`, `winRm`, `dcomExec`, `spawnAs`, `makeToken`, etc.) sans exposer les mots de passe. |
| 28 | [ ] | Ajouter historique/audit operateur cote serveur | XL | Tres fort | Qui a envoye quoi, quand, sur quelle session, command_id, resultat, statut. Base pour recherche, replay, reporting. |
| 29 | [ ] | Ajouter `GetCommandStatus` / `ListCommandHistory` / `CancelCommand` | XL | Tres fort | Suivi propre des commandes queued/running/done/error/cancelled; utile pour console, assistant et workflows longs. |
| 30 | [ ] | Ajouter tags/notes/assignation sessions cote serveur | XL | Fort | Tags persistants, notes operationnelles, owner operateur, priorite, commentaires. |
| 31 | [ ] | Ajouter `StreamEvents` global | XL | Tres fort | Flux unique pour sessions, listeners, commandes, logs et erreurs; remplacer le polling toutes les 2 secondes. |
| 32 | [ ] | Ajouter upload/download chunked avec progression | XL | Fort | Progression, checksum, reprise partielle, erreurs propres, limites configurables. |

## Details `.env`

La gestion `.env` est une bonne direction parce qu'elle reduit la friction de lancement et evite de disperser la config entre CLI, variables shell, assistant et chemins locaux. Le comportement recommande:

- Priorite: arguments CLI > variables d'environnement deja presentes > fichier `C2_ENV_FILE` > `.env` du cwd > `C2Client/.env` > defaults internes.
- Ne jamais versionner `C2Client/.env`; garder seulement `C2Client/.env.example`.
- Charger `.env` une seule fois au demarrage, puis exposer la config active dans la barre de statut sans afficher les secrets.
- Resoudre les chemins de `.env` depuis le dossier du fichier `.env`, pour que `C2_CERT_PATH=../TeamServer/server.crt` fonctionne.
- Masquer `C2_PASSWORD`, `OPENAI_API_KEY`, tokens GitHub/listener et autres secrets dans tous les logs/UI.

Variables client a centraliser:

```dotenv
# TeamServer connection
C2_IP=127.0.0.1
C2_PORT=50051
C2_DEV_MODE=false
C2_CERT_PATH=
C2_USERNAME=
C2_PASSWORD=

# Generated protocol
C2_PROTOCOL_PYTHON_ROOT=

# Client UI
C2_UI_THEME=dark
C2_SESSION_REFRESH_MS=2000
C2_SESSION_STALE_AFTER_MS=30000
C2_LISTENER_REFRESH_MS=2000
C2_GRAPH_REFRESH_MS=2000
C2_LOG_DIR=
C2_LOG_LEVEL=WARNING

# gRPC
C2_GRPC_CONNECT_TIMEOUT_MS=10000
C2_GRPC_MAX_MESSAGE_MB=512

# Assistant
OPENAI_API_KEY=
C2_ASSISTANT_MODEL=gpt-4.1-mini
C2_ASSISTANT_MEMORY_MODEL=gpt-4.1-mini
C2_ASSISTANT_TEMPERATURE=0.05
C2_ASSISTANT_MEMORY_TEMPERATURE=0.05
C2_ASSISTANT_MAX_TOOL_CALLS=10
C2_ASSISTANT_PENDING_TIMEOUT_MS=120000

# Local modules
C2_DROPPER_MODULES_DIR=
C2_SHELLCODE_MODULES_DIR=
```

## Proposition de phases

1. Phase 1: items 1 a 8. Aucun changement proto, beaucoup d'UX gagnee vite.
2. Phase 2: items 9 a 16. Client plus productif, tables/console/graph vraiment exploitables.
3. Phase 3: items 17 a 26. Contrat client-server propre pour capabilities, commandes, erreurs, SOCKS5 et artefacts generes par flux.
4. Phase 4: items 27 a 32. Fonctionnalites operationnelles avancees, credential store serveur, audit et reduction du polling.
