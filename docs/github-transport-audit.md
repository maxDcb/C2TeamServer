# Audit du transport GitHub

Date : 24 octobre 2026

Périmètre : parcours Client/TeamServer → `ListenerGithub` → API GitHub Issues → `BeaconGithub`, implémentations Windows et Linux, gestion du jeton, fiabilité de livraison et tests.

## Conclusion

Le transport GitHub doit rester désactivé par défaut avec `C2_ENABLE_GITHUB_TRANSPORT=OFF`.

La variante activée compile, mais le contrat TeamServer/listener/beacon n'est pas opérationnel de manière fiable : les issues ne sont pas fermées correctement, des tâches et résultats peuvent être perdus, une commande peut être rejouée, et la beacon Linux n'est pas implémentée.

## Contrat observé

1. La beacon publie une issue `ResponseC2: <beaconHash>` contenant son check-in et ses résultats.
2. Le listener interroge les issues ouvertes du dépôt et transmet le corps à `Listener::handleMessages`.
3. Si une tâche est disponible, le listener crée une issue `RequestC2: <beaconHash>`.
4. La beacon recherche cette issue, transforme son corps en tâches puis tente de la fermer.
5. Le listener tente également de fermer l'issue de réponse traitée.

Les corps utilisent le format Protobuf commun, XOR puis Base64. Le titre de l'issue assure le routage visible, mais il n'existe aucun identifiant d'échange, acquittement de livraison ou mécanisme de déduplication.

## P0 — blocages avant activation

| Identifiant | Problème | Preuve | Conséquence |
| --- | --- | --- | --- |
| GH-P0-01 | Les issues sont fermées avec `POST` au lieu de `PATCH`. | [`ListenerGithub.cpp`](../core/listener/ListenerGithub.cpp#L244) et [`BeaconGithub.cpp`](../core/beacon/BeaconGithub.cpp#L352). L'API GitHub « Update an issue » exige `PATCH /repos/{owner}/{repo}/issues/{issue_number}`. | Les issues restent ouvertes. Les résultats sont retraités et une issue de tâche peut être exécutée plusieurs fois. Les statuts HTTP de fermeture sont ignorés. |
| GH-P0-02 | La livraison retire les données des files avant leur publication. | [`Beacon::taskResultsToCmd`](../core/beacon/Beacon.cpp#L492) vide `m_taskResult`. [`Listener::handleMessages`](../core/listener/Listener.cpp#L719) retire les tâches en attente. `ListenerGithub` n'utilise ni `dequeuedTasks` ni `restoreTasks`. | Un échec de création d'issue perd définitivement les résultats de la beacon ou les tâches du TeamServer. |
| GH-P0-03 | Une erreur du listener peut arrêter le TeamServer. | Le thread démarre avant l'initialisation du logger, le parsing JSON du thread n'est pas protégé et `m_isRunning` est un `bool` partagé non atomique dans [`ListenerGithub`](../core/listener/ListenerGithub.cpp#L8). | Déréférencement possible d'un logger nul, `std::terminate` sur exception sortant du thread et course mémoire à l'arrêt. Cela viole le contrat selon lequel l'échec d'un listener ne doit pas arrêter le programme. |
| GH-P0-04 | La beacon Linux est un stub. | La branche Linux de [`BeaconGithub::checkIn`](../core/beacon/BeaconGithub.cpp#L392) ne contient que du code commenté. | Le binaire peut être compilé et distribué lorsque l'option est active, mais ne réalise aucun check-in. |
| GH-P0-05 | Le jeton GitHub est exposé par le TeamServer. | Le jeton complet est écrit dans le log de création et renvoyé par `ListListeners` dans [`TeamServerListenerSessionService.cpp`](../teamServer/teamServer/TeamServerListenerSessionService.cpp#L186). `infoListener` renvoie aussi `param2` dans [`TeamServerListenerArtifactService.cpp`](../teamServer/teamServer/TeamServerListenerArtifactService.cpp#L133). | Toute personne ou collecte de logs ayant accès à ces sorties peut récupérer le secret. Le launcher reçoit également le jeton dans la ligne de commande du processus. |
| GH-P0-06 | Le launcher DLL Windows lit hors limites. | [`BeaconGithubLauncher.cpp`](https://github.com/maxDcb/C2Implant/blob/021c75e/beacon/beacon/BeaconGithubLauncher.cpp#L45) accepte une taille de deux, puis accède à `splitedCmd[2]`. | Comportement indéfini ou crash au lancement DLL. |

## P1 — fiabilité, capacité et sécurité

### Polling et quotas GitHub

- Le listener interroge `/issues` toutes les secondes : environ 3 600 requêtes par heure lorsqu'il fonctionne normalement.
- Une beacon Windows, avec une période de dix secondes, effectue au minimum un `POST` et un `GET` par cycle : environ 720 requêtes par heure.
- Un listener et deux beacons consomment donc déjà au moins 5 040 requêtes par heure, sans compter les fermetures d'issues et les commentaires. Le quota personnel authentifié courant est de 5 000 requêtes par heure.
- Les erreurs réseau et statuts non réussis utilisent `continue` avant le délai d'une seconde. Un jeton invalide ou une limitation peut donc provoquer une boucle sans temporisation.
- Le code n'interprète ni `Retry-After`, ni `X-RateLimit-Remaining`, ni `X-RateLimit-Reset`, et n'applique aucun backoff exponentiel.
- Les requêtes ne sont pas conditionnelles (`ETag`/`If-None-Match`).

Références :

- [Rate limits for the REST API](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
- [Best practices for using the REST API](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api)

### Sélection et pagination

- Le listing n'utilise ni label dédié, ni auteur attendu, ni autre propriété permettant d'isoler strictement le trafic C2.
- L'API Issues peut également renvoyer des Pull Requests.
- La réponse est paginée à 30 éléments par défaut. Aucun `Link`, `page` ou `per_page` n'est traité.
- La beacon télécharge les commentaires de chaque issue avant de vérifier si son titre et son `beaconHash` la concernent.
- Les corps JSON sont supposés présents et du bon type. Un `body: null` ou une réponse partielle peut lever une exception.

Références :

- [REST API endpoints for issues](https://docs.github.com/en/rest/issues/issues)
- [Using pagination in the REST API](https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api)

### Livraison, rejeu et fragmentation

- Il n'existe aucun `message_id`, numéro de séquence, acquittement ou cache de messages déjà traités.
- La fermeture d'une issue tient lieu d'acquittement implicite, alors qu'elle échoue actuellement et que son résultat n'est pas vérifié.
- Le listener découpe une réponse à 65 000 caractères, mais les fragments n'ont ni index, ni nombre total, ni empreinte d'intégrité.
- Un commentaire absent, dupliqué ou lu dans un ordre inattendu corrompt silencieusement le message.
- Une création partielle de commentaires n'est pas transactionnelle.
- La beacon Windows ne fragmente pas ses résultats volumineux.
- `cmdToTasks` ignore le résultat de `ParseFromArray`, puis l'issue est fermée même si la commande est invalide.

### Ressources et cycle de vie

- `GithubGet` Windows ne ferme pas `hRequest`, `hConnect` et `hSession`. Trois handles WinHTTP sont perdus à chaque lecture.
- Les clients ne définissent pas explicitement de délais de connexion, lecture et écriture adaptés au cycle de vie de la beacon ou du listener.
- L'arrêt du listener ne dispose d'aucun mécanisme d'annulation de la requête en cours.
- Le TeamServer annonce immédiatement « Listener created » sans vérifier le dépôt, le jeton et les permissions.
- Le serveur peut proposer un artefact GitHub Linux alors que son implémentation est vide.
- Le client Python continue d'afficher GitHub parmi les types principaux même lorsque la capacité est absente du build du TeamServer.

### Secrets et authenticité

- Le jeton existe simultanément dans les paramètres génériques du listener, `m_token`, les réponses gRPC et les arguments du processus.
- Les dix premiers caractères sont également placés dans les métadonnées du listener ; cette fuite partielle n'est pas nécessaire.
- Le XOR est une obfuscation, pas une protection d'intégrité ou une authentification du message.
- Toute identité autorisée à écrire une issue compatible peut injecter ou rejouer un message si elle possède le format et la clé intégrée.
- Le transport devrait utiliser un dépôt privé dédié et un jeton fine-grained limité à ce dépôt avec seulement `Issues: read/write`.
- `Authorization: token` reste accepté par GitHub, mais `Bearer` et un en-tête `X-GitHub-Api-Version` explicite rendraient le contrat API plus clair.

Le contrôle TLS est en revanche actif : `cpp-httplib 0.62.0` vérifie le certificat serveur par défaut et WinHTTP conserve la validation TLS système.

### Sorties textuelles de la beacon

`BeaconGithub.cpp` contient plusieurs `printf` et `std::cout` affichant erreurs, endpoints, tailles et étapes du check-in. Ils violent la règle commune selon laquelle aucune erreur textuelle ne doit apparaître dans les programmes beacon/listener.

## Tests existants

Les cibles `testListenerGithub` et `testBeaconGithub` compilent avec `C2_ENABLE_GITHUB_TRANSPORT=ON`, mais elles vérifient seulement la construction des objets.

- `testBeaconGithub` construit une beacon puis retourne immédiatement.
- `testListenerGithub` démarre un vrai thread et contacte directement `api.github.com` avec un faux jeton.
- Lors de l'audit, ce test a reçu `401 Bad credentials`, puis a tout de même terminé avec succès.
- Aucun test ne vérifie le parcours résultat → issue de réponse → tâche → issue de requête → exécution → acquittement.

Ces tests ne doivent pas dépendre du réseau public dans la suite automatisée.

## Couverture contractuelle à ajouter

Le client HTTP GitHub doit être injecté derrière une interface afin d'utiliser un faux serveur ou un transport en mémoire dans les tests.

1. Check-in sans tâche et check-in avec une tâche.
2. Livraison d'un résultat puis d'une tâche avec acquittement complet.
3. Échec réseau ou HTTP à chaque étape, en vérifiant que les files ne sont pas vidées.
4. Relecture de la même issue, en vérifiant qu'un `message_id` n'est traité qu'une fois.
5. Fermeture par `PATCH` et validation du statut HTTP.
6. Pagination de plusieurs pages, exclusion des Pull Requests et gestion de `body: null`.
7. Réponses 401, 403 et 429 avec temporisation bornée, `Retry-After` et backoff.
8. Fragments complets, absents, dupliqués, désordonnés ou avec une empreinte invalide.
9. JSON, Base64 et Protobuf invalides sans arrêt du TeamServer ni de la beacon.
10. Arrêt du listener pendant une requête lente ou bloquée.
11. Vérification qu'aucun jeton n'apparaît dans les logs, métadonnées ou réponses non nécessaires.
12. Même suite de contrat exécutée contre les implémentations Windows et Linux.
13. Test réel optionnel, jamais exécuté par défaut, sur un dépôt privé jetable.

## Ordre de reprise recommandé

### Étape 1 — sécuriser le socle

- Remplacer la fermeture `POST` par `PATCH`.
- Vérifier tous les statuts HTTP avant de modifier l'état local.
- Initialiser complètement le listener avant de démarrer son thread.
- Encadrer toute la boucle du thread par une barrière d'exception.
- Rendre l'état d'arrêt atomique et rendre les requêtes annulables.
- Corriger le parsing du launcher DLL.
- Supprimer toute sortie du jeton et toute sortie textuelle côté beacon.
- Ne pas proposer l'artefact Linux tant que son implémentation est absente.

### Étape 2 — rendre le protocole transactionnel

- Ajouter une enveloppe versionnée avec `message_id`, direction, `beacon_hash`, date d'expiration et type de message.
- Conserver tâches et résultats jusqu'à un acquittement valide.
- Ajouter un cache borné de déduplication des messages reçus.
- Définir explicitement la sémantique de reprise après un crash.

### Étape 3 — fiabiliser les charges volumineuses

- Ajouter `chunk_index`, `chunk_count`, taille totale et empreinte du message complet.
- N'acquitter et ne décoder que lorsque tous les fragments sont présents et valides.
- Appliquer la fragmentation dans les deux directions.

### Étape 4 — client GitHub commun

- Centraliser méthodes HTTP, en-têtes, timeouts, pagination, requêtes conditionnelles et politique de retry.
- Utiliser une interface commune testable pour le listener, Windows et Linux.
- Fermer systématiquement toutes les ressources WinHTTP avec RAII.
- Implémenter la beacon Linux avec le même contrat.

### Étape 5 — validation avant réactivation

- Exécuter la suite contractuelle sans réseau externe.
- Valider Windows et Linux avec le TeamServer réel.
- Exécuter le test live opt-in sur un dépôt privé temporaire.
- Exposer la capacité GitHub au client uniquement lorsque le TeamServer la déclare disponible.
- Maintenir `C2_ENABLE_GITHUB_TRANSPORT=OFF` jusqu'à réussite de toutes ces validations.

## Décision actuelle

Le code reste conservé pour une expérimentation future, derrière une option de compilation explicite non activée par défaut. Aucune correction fonctionnelle GitHub n'a été appliquée pendant cet audit.
