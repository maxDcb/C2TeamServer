# Tâches LLM du client C2

La vue **Data AI → Tâches** lance un skill `inventory_local` sur la session
sélectionnée. Son plan, versionné dans le client, exécute `whoami` puis
`ipConfig`. Les deux modules doivent être chargés sur la session avant le
lancement. Le LLM interprète les résultats observés dans un rapport structuré ;
il ne choisit ni ne modifie les commandes du plan.

## Propriété et reprise

Le client possède l'ordonnanceur et les fichiers de tâche dans
`C2Client/C2Client/logs/assistant_sessions/skills/runs/`. Le TeamServer possède
les jobs, leurs résultats et leurs événements V2 dans SQLite. Chaque étape a
un `job_id` stable. Après un redémarrage du client, les tâches inachevées sont
relues, les jobs sont interrogés avec `GetJobExecution`, puis le suivi des
événements reprend. Une soumission dont la réponse s'est perdue est vérifiée
par son `job_id` avant d'être retentée avec **le même identifiant**.

Une commande peut rester en attente sans délai automatique, y compris lorsque
le serveur indique `outcome_unknown`. L'opérateur peut déclarer **Résultat
absent** avec une raison ; l'étape devient incertaine et le rapport est partiel.
**Mettre en échec** clôt la tâche entière. Aucune de ces actions n'annule une
commande déjà envoyée au beacon. Un résultat tardif est enregistré comme état
tardif et ne réécrit pas un rapport déjà terminé.

Les sorties exactes de jobs réussis sont encodées en base64 dans le journal de
tâche. Le rapport donne un aperçu de 16 000 octets, une taille et un SHA-256.
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
C2Client/.venv/bin/python -m pip install -e /home/mdecaumiabaillenx/Challenges/agent-core --no-deps --no-build-isolation
C2_PROTOCOL_PYTHON_ROOT="$PWD/build/generated/python_protocol" \
  QT_QPA_PLATFORM=offscreen \
  C2Client/.venv/bin/python -m pytest C2Client/tests -q
```

La dépendance `agent-core` du `pyproject.toml` pointe encore sur la version
publiée précédente. Le second `pip install -e` est donc requis pour utiliser
le commit local non poussé. Ne pas supprimer le checkout local tant qu'il est
utilisé par cet environnement virtuel.

Pour démarrer l'interface avec les identifiants Azure déjà présents dans le
fichier `.env` de PentestAssistant, définir le chemin du fichier et le nom du
déploiement Azure utilisé par ce compte :

```bash
export C2_ENV_FILE=/home/mdecaumiabaillenx/Challenges/PentestAssistant/.env
export C2_ASSISTANT_MODEL='<nom-du-déploiement-Azure>'
export C2_PROTOCOL_PYTHON_ROOT="$PWD/build/generated/python_protocol"
C2Client/.venv/bin/python -m C2Client.GUI
```

`C2_ENV_FILE` charge `LLM_PROVIDER`, `AZURE_OPENAI_ENDPOINT` et
`AZURE_OPENAI_API_KEY` sans copier le secret dans ce dépôt. Le modèle peut
également être configuré avec `C2_ASSISTANT_PROVIDER`, `OPENAI_API_KEY` et
`C2_ASSISTANT_MODEL` pour OpenAI. Les tâches n'avancent que lorsque le client
est ouvert ; le TeamServer peut continuer à recevoir une réponse beacon pendant
son absence.
