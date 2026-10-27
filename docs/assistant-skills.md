# Tâches LLM du client C2

## Agent Skills et capacités C2

### Bundles de capacités C2

Les skills agentiques associent désormais leur `SKILL.md` portable à un fichier
`skill.yaml` contrôlé par le client. Le manifeste indique les bundles métier,
les outils requis, les observations nécessaires à un rapport complet, l'objectif
et les limites d'appels. Les dossiers qui contiennent ces deux fichiers sont
découverts automatiquement au démarrage du client. `identify-user` demande
`recon.identity`, qui n'accorde que `whoami`. La liste résolue est enregistrée
dans le run pour que sa reprise conserve les mêmes permissions après une mise
à jour du catalogue.

Le catalogue [`bundles.py`](../C2Client/C2Client/assistant_agent/capabilities/bundles.py)
recense les capacités par objectif : `recon.identity`, `recon.host`, `exec`, `pivot`, `file_ops`,
`payload_delivery`, `credentials` et `session_management`. Il inclut les
commandes beacon et les opérations TeamServer ou locales destinées aux futurs
adaptateurs, notamment SOCKS, hébergement d'artifact et génération de dropper.
Le résolveur ne transmet à agent-core que les outils réellement enregistrés ;
un outil requis absent fait échouer le démarrage du skill. Le catalogue et ses
tests résident dans `assistant_agent/capabilities`, car il est partagé par les
skills et la conversation. Le catalogue des définitions de skills reste dans
`assistant_agent/skills`.

`recon-host` est le premier skill agentique multi outils. Il associe
`recon.identity` et `recon.host`, exige `whoami`, `ipConfig` et
`listC2Listeners`, puis laisse le LLM choisir ses appels dans la limite de dix
outils. Le client fixe la session, valide chaque argument, charge un module
manquant, crée un job V2 stable avant l'envoi de chaque commande et attend son
résultat. Le run conserve la liste des outils, leurs spécifications, les jobs,
les octets exacts et les observations TeamServer. Le curseur V2 et l'identifiant
de l'événement terminal de chaque job sont enregistrés, y compris lorsque le
polling `GetJobExecution` constate le résultat avant le flux. Après redémarrage,
le client relit les événements du job en cours depuis le curseur, vérifie son
état puis reprend les choix du LLM sans renvoyer une commande déjà acceptée.
Le rapport cite les `job_id` et les
`observation_id` réellement observés ; une citation inventée invalide l'analyse.
Un rapport sans résultat réussi de `whoami`, `ipConfig` et `listC2Listeners`
reste partiel, même si le modèle conclut autrement.

Sur Windows et Linux, `recon.host` expose aussi `hostContext` pour collecter le
nom d'hôte, la version de l'OS et du noyau, la configuration du résolveur et les routes IPv4.
Le module `netstat` restitue les adresses dans l'ordre réseau, nomme les états
et associe les sockets aux processus lorsque `/proc/<pid>/fd` est accessible.
L'absence d'association reste explicite (`Owner:unknown`). `hostContext` est
facultatif si le module n'est pas chargé ; le skill signale les observations non
collectées plutôt que de les inventer.

Les adaptateurs `listC2Listeners` et `listC2Artifacts` sont des lectures
TeamServer utilisables par la conversation et les skills. `hostArtifact` et
`socksControl` sont des opérations terminal typées utilisables par la
conversation ; elles ne donnent pas accès à une commande terminal libre. Les
opérations terminal à effet de bord ne sont pas encore enregistrées dans les
runs de skills, car leur exécution ne possède pas d'identifiant de job V2 pour
récupérer avec certitude une réponse perdue. La génération de dropper reste
liée à son parcours local et demande encore un adaptateur sans widget Qt. Le
plan fixe `inventory_local` et le skill `identify-user` restent disponibles.

## Premier skill agentique : identify-user

Le dossier `C2Client/C2Client/assistant_agent/skills/identify-user/` contient un
`SKILL.md` au format [Agent Skills](https://agentskills.io/specification) :
frontmatter YAML `name` et `description`, puis instructions Markdown. Le client
charge ces instructions dans un `StructuredTaskSpec` d'agent-core. Le modèle
choisit d'appeler le tool `whoami` ; le client fixe la session choisie par
l'opérateur et n'expose aucun autre tool à ce run.

L'appel au tool crée un job V2 avec un identifiant stable et retourne `pending`
à agent-core. Le client attend le résultat, y compris après redémarrage, puis
appelle `resume_pending_tool` avec la sortie observée. Si `whoami` nécessite un
module, son chargement est un prérequis technique suivi par le client ; le
modèle reçoit la sortie de `whoami`, jamais le résultat du chargement comme
preuve d'identité. **No result** peut terminer l'attente avec un rapport
partiel. Le rapport et les octets exacts des jobs restent dans le journal local.

Le format `SKILL.md` apporte les instructions portables. La permission effective
du tool et le périmètre de session sont imposés par le code du client ; les
instructions Markdown ne peuvent pas les élargir. Le premier skill reste
volontairement limité à un seul appel. `inventory_local` ci-dessous conserve son
ancien plan fixe pour les runs déjà enregistrés.

La liste des tâches indique **Agent** pour `identify-user` et **Fixed** pour
`inventory_local`. Le bouton **?** donne la description et la méthode de la
tâche au survol ou au clic. Les runs sont dans un menu déroulant ; le rapport
conserve sa position de lecture lors des rafraîchissements. L'entrée **Any
session** est visible pour préparer les futurs skills multi sessions, mais
reste désactivée : les deux skills présents exigent une session précise.

## Inventaire local à plan fixe

La vue **Data AI → Tasks** propose directement les sessions actives du
TeamServer. Elle sélectionne automatiquement la seule session disponible ;
sinon, choisir une session dans la liste puis cliquer sur **Start**. Le bouton
**Refresh** recharge les sessions sans ouvrir de console. Le skill
`inventory_local`, versionné dans le client, exécute `whoami` puis
`ipConfig`. Si un module manque, le client exécute d'abord `loadModule` et
attend sa réponse ; ce chargement possède son propre job et reprend après
redémarrage du client. Un module déjà en cours de chargement est suivi par son
identifiant existant, sans nouvelle soumission. La réponse précise
`Module already loaded` du beacon valide également ce prérequis : le job de
chargement conserve son état brut d'échec dans les preuves, puis la commande
demandée est envoyée. Les autres échecs de chargement restent des échecs.
Le LLM interprète les résultats observés dans un rapport structuré en anglais ;
il ne choisit ni ne modifie les commandes du plan.

La vue Tasks présente le rapport sous forme de phrases et garde les identifiants
de jobs, états bruts et sorties dans **Show execution details**. Le stockage
conserve le rapport structuré et les preuves exactes pour la reprise et l'audit.

La conversation applique la même précondition : un appel à un outil de module
charge automatiquement ce module s'il manque, attend le résultat du chargement,
puis envoie la commande demandée. `outcome_unknown` maintient l'attente jusqu'à
un résultat tardif ou `/stop`. Le chargement réussi seul n'est jamais présenté
comme le résultat de la commande demandée. Une réponse `Module already loaded`
enchaîne également sur la commande demandée.

## Propriété et reprise

Le client possède l'ordonnanceur et les fichiers de tâche dans
`C2Client/C2Client/logs/assistant_sessions/skills/runs/`. Le TeamServer possède
les jobs, leurs résultats et leurs événements V2 dans SQLite. Chaque étape a
un `job_id` stable. Après un redémarrage du client, les tâches inachevées sont
relues, les jobs sont interrogés avec `GetJobExecution`, puis le suivi des
événements reprend. Une soumission dont la réponse s'est perdue est vérifiée
par son `job_id` avant d'être retentée avec **le même identifiant**.

Une commande peut rester en attente sans délai automatique, y compris lorsque
le serveur indique `outcome_unknown`. L'opérateur peut déclarer **No result**
avec une raison ; l'étape devient incertaine et le rapport est partiel.
**Mark failed** clôt la tâche entière. Aucune de ces actions n'annule une
commande déjà envoyée au beacon. Un résultat tardif est enregistré comme état
tardif et ne réécrit pas un rapport déjà terminé.

Les sorties exactes de jobs réussis sont encodées en base64 dans le journal de
tâche. Le rapport donne un aperçu de 16 000 octets, une taille et un SHA-256.
Les résultats de `loadModule` restent dans les preuves mais ne sont pas cités
comme des observations de l'inventaire.
Une sortie rejetée par la limite du serveur apparaît comme échec du job ; elle
n'est pas présentée comme preuve complète. Si le LLM échoue, les preuves restent
consultables et le rapport est marqué partiel, avec analyse indisponible.

Le rapport utilise `AgentRunService` et `StructuredTaskSpec` d'agent-core.
L'ordonnancement du plan fixe et la décision de clôture manuelle restent dans
le client. `agent-core` expose aussi la suspension et la reprise de tools
externes pour les tâches structurées, sur le même principe que la conversation,
sans changer les appels existants de PentestAssistant.

## Installation et tests locaux

Depuis la racine de C2TeamServer, après génération des bindings Python par le
build CMake (voir [build.md](build.md)) :

```bash
python3 -m venv C2Client/.venv
C2Client/.venv/bin/python -m pip install -e './C2Client[test]'
C2_PROTOCOL_PYTHON_ROOT="$PWD/build/generated/python_protocol" \
  QT_QPA_PLATFORM=offscreen \
  C2Client/.venv/bin/python -m pytest C2Client/tests -q
ctest --test-dir build -R '^(testsNetstat|testsHostContext|testsJobRuntimeE2E)$' \
  --output-on-failure --timeout 120
```

La dépendance `agent-core` est figée sur le commit qui fournit la suspension et
la reprise des tâches structurées. Pour développer les deux dépôts ensemble,
il est possible d'installer le checkout local après le client avec
`C2Client/.venv/bin/python -m pip install -e /home/mdecaumiabaillenx/Challenges/agent-core --no-deps --no-build-isolation`.

Pour démarrer l'interface avec la configuration locale actuelle (le fichier
`C2Client/.env` sélectionne Azure et `gpt-5.5`) :

```bash
export C2_PROTOCOL_PYTHON_ROOT="$PWD/build/generated/python_protocol"
C2Client/.venv/bin/python -m C2Client.GUI
```

Le lien local `.env` à la racine lit les identifiants de PentestAssistant et
`C2Client/.env` choisit le modèle, sans copier la clé dans ce dépôt. Le modèle peut également être configuré avec
`C2_ASSISTANT_PROVIDER`, `OPENAI_API_KEY` et `C2_ASSISTANT_MODEL` pour OpenAI.
Les tâches n'avancent que lorsque le client est ouvert ; le TeamServer peut
continuer à recevoir une réponse beacon pendant son absence.
