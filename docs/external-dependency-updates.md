# Versions publiées des paquets Conan et pip

Relevé initial du 24 octobre 2026. Sources : manifestes [`conanfile.txt`](../conanfile.txt), [client pip](../C2Client/pyproject.toml), [implant Linux](c2implant-linux-inventory.md), [implant Windows](c2implant-windows-inventory.md), catalogue distant Conan Center interrogé avec `conan list` et index PyPI. Les colonnes « version initiale » décrivent l'état avant les mises à jour. « Plus récente » signifie version publiée, pas compatibilité validée avec le projet.

## Mise à jour appliquée

- Python `>=3.12` pour le client et Python `3.12` / Conan `2.24.0` dans les CI des deux implants.
- Conan : gRPC `1.84.0` sur TeamServer ; cpp-httplib `0.62.0` sur TeamServer et Linux ; OpenSSL `3.6.5` sur les trois parents (dépendance directe ajoutée au Windows pour remplacer la version transitive `3.6.2`) ; Catch2 `3.16.0` sur Linux. Le lock Conan du TeamServer a été régénéré.
- pip : pycryptodome `3.24.1`, grpcio `1.84.1`, PyQt6 `6.11.0`, GitPython `3.2.1`, requests `2.34.2`, openai `3.37.0`, Markdown `3.11.2`, PyYAML `6.0.3` et pytest `9.1.1`.
- `pyqtdarktheme` a été remplacé par [`qt-material` 2.17](https://pypi.org/project/qt-material/). Les modes `dark`, `light`, `native` et `none` de `C2_UI_THEME` sont conservés. Les ressources du client sont maintenant résolues depuis les fichiers du paquet, sans `pkg_resources`.
- Validations locales : TeamServer compilé sous WSL, 78/78 CTest ; implant Linux compilé sous WSL, 62/62 CTest ; implant Windows compilé avec MSVC x64, 58/58 CTest ; client Python 3.12, 257/257 tests sous WSL et Windows, 5/5 tests de packaging sur chaque plateforme. Le bundle de release TeamServer est validé.

## Conan

| Paquet | Version initiale | Plus récente sur Conan Center | Proposition initiale |
| --- | --- | --- | --- |
| [`grpc`](https://conan.io/center/recipes/grpc) | 1.78.1 (TeamServer) | 1.84.0 | Mise à jour coordonnée avec `grpcio` Python et tests du protocole |
| [`protobuf`](https://conan.io/center/recipes/protobuf) | 6.33.5 (TeamServer) | 7.36.2 | Garder 6.33.5 pour cette passe : dernière version Conan de la ligne 6 et même version que pip ; étudier la migration 7 séparément |
| [`spdlog`](https://conan.io/center/recipes/spdlog) | 1.17.0 (TeamServer) | 1.17.0 | À conserver |
| [`cpp-httplib`](https://conan.io/center/recipes/cpp-httplib) | 0.39.0 (TeamServer, Linux) | 0.62.0 | Mise à jour séparée avec tests des listeners/beacons HTTP et WebSocket |
| [`openssl`](https://conan.io/center/recipes/openssl) | 3.6.2 (TeamServer, Linux) | 4.0.3 | Essayer 3.6.5, dernière version Conan de la ligne 3 ; réserver la migration majeure 4 |
| [`nlohmann_json`](https://conan.io/center/recipes/nlohmann_json) | 3.12.0 (trois parents) | 3.12.0 | À conserver |
| [`libssh2`](https://conan.io/center/recipes/libssh2) | 1.11.1 (trois parents) | 1.11.1 | À conserver |
| [`catch2`](https://conan.io/center/recipes/catch2) | 3.14.0 (tests Linux) | 3.16.0 | Mettre à jour avec les tests Linux |

Un graphe Conan candidat `grpc/1.84.0`, `protobuf/6.33.5`, `cpp-httplib/0.62.0`, `openssl/3.6.5` et les autres dépendances TeamServer actuelles se résout avec le profil Linux GCC 13. Le graphe Linux avec `catch2/3.16.0` se résout aussi. Cette opération n'a compilé aucun paquet ni le projet ; elle indique des binaires gRPC et Catch2 manquants pour les configurations exactes du profil examiné. Un build peut donc nécessiter une compilation de ces paquets.

## pip : dépendances directes du client

| Paquet | Version initiale | Plus récente sur PyPI | Proposition initiale |
| --- | --- | --- | --- |
| [`pycryptodome`](https://pypi.org/project/pycryptodome/) | 3.23.0 | 4.2.0 | Essayer 3.24.1 dans la ligne 3 ; migration 4 séparée |
| [`grpcio`](https://pypi.org/project/grpcio/) | 1.78.0 | 1.84.1 | Mettre à jour avec `grpc` Conan 1.84.0 ; ne pas viser 1.78.1, version Python [retirée](https://pypi.org/project/grpcio/1.78.1/) |
| [`PyQt6`](https://pypi.org/project/PyQt6/) | 6.7.0 | 6.11.0 | Essayer séparément avec les tests GUI |
| [`pyqtdarktheme`](https://pypi.org/project/pyqtdarktheme/) | Non épinglé | 2.1.0 | Proposition initiale abandonnée : remplacé par `qt-material` 2.17 |
| [`protobuf`](https://pypi.org/project/protobuf/) | 6.33.5 | 7.36.2 | Garder 6.33.5, aligné avec Conan ; PyPI 6.33.6 existe mais pas dans les recettes Conan relevées |
| [`GitPython`](https://pypi.org/project/GitPython/) | 3.1.61 | 3.2.1 | Mise à jour candidate avec tests des modules Git du client |
| [`requests`](https://pypi.org/project/requests/) | 2.33.0 | 2.34.2 | Mise à jour candidate avec tests Batcave/HTTP |
| [`pwn`](https://pypi.org/project/pwn/) | 1.0 | 1.0 | À conserver pour cette passe ; vérifier ensuite son usage via `ElfDropper` |
| [`pefile`](https://pypi.org/project/pefile/) | 2024.8.26 | 2024.8.26 | À conserver |
| [`openai`](https://pypi.org/project/openai/) | 3.36.1 | 3.37.0 | Mise à jour candidate avec tests de l'assistant et d'`agent-core` |
| [`Markdown`](https://pypi.org/project/Markdown/) | Non épinglé | 3.11.2 | Épingler dans un environnement reproductible |
| [`PyYAML`](https://pypi.org/project/PyYAML/) | `>=6,<7` | 6.0.3 | Épingler dans un environnement reproductible ; ajouter aussi à `requirements.txt` |
| [`pytest`](https://pypi.org/project/pytest/) | 9.0.3 (tests) | 9.1.1 | Mise à jour facultative des tests |
| [`pytest-qt`](https://pypi.org/project/pytest-qt/) | 4.5.0 (tests) | 4.5.0 | À conserver |

`setuptools` et `wheel` sont déclarés sans version pour le build du client ; leurs versions publiées relevées sont respectivement 84.2.1 et 0.48.0. Le dépôt `agent-core`, épinglé par commit, déclare huit dépendances pip avec des plages de versions, sans lock transitive partagé avec le client. Le fork `donut-shellcode` reste référencé par `master` dans les deux manifestes pip.

Avant la mise à jour, `pyqtdarktheme` n'était importé que dans [`GUI.py`](../C2Client/C2Client/GUI.py) pour appliquer la feuille de style globale. Le client possède ses propres styles de panneaux dans [`panel_style.py`](../C2Client/C2Client/panel_style.py). Le remplacement par `qt-material` a été validé sur les thèmes sombre et clair sous Windows et WSL.

Le premier essai de résolution sous Python 3.12 utilisait `pyqtdarktheme 0.1.7` ; `pyqtdarktheme 2.1.0` était incompatible avec sa contrainte Python. L'installation et les tests finaux utilisent `qt-material 2.17`.

## Étapes envisagées lors du relevé initial

1. Mettre à jour les corrections dans les lignes actuelles : OpenSSL 3.6.5, pycryptodome 3.24.1, GitPython 3.2.1, requests 2.34.2 et openai 3.37.0 ; traiter le thème Qt et les dépendances pip encore flottantes.
2. Traiter gRPC C++ 1.84.0 et Python 1.84.1 ensemble, en gardant Protobuf 6.33.5 ; valider compilation, génération des stubs et échanges TeamServer/client.
3. Traiter cpp-httplib 0.62.0 avec les tests HTTP/WebSocket ; PyQt6 6.11.0 avec les tests GUI ; Catch2 3.16.0 avec les tests Linux.
4. Reporter les migrations majeures Protobuf 7, OpenSSL 4 et pycryptodome 4 jusqu'à l'examen de leurs changements d'API et de leurs impacts sur les trois builds.

## Alignement des environnements CI

Avant la mise à jour, les workflows CI et release du TeamServer sélectionnaient Python `3.12` et Conan `2.24.0`, tandis que ceux des implants demandaient Python `3.x` et Conan `>=2,<3`. Les implants utilisent Python pour la génération de leur configuration et Conan pour le build ; le client déclarait `requires-python = ">=3.11"`.

Les quatre workflows des implants sélectionnent maintenant Python `3.12` et Conan `2.24.0` ; le client déclare `requires-python = ">=3.12"`. Les tests du client ont été exécutés localement sur Windows et WSL avec Python 3.12.
