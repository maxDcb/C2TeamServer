# Index des inventaires Exploration C2

État du catalogue au 24 octobre 2026. Il porte sur les dépôts parents, leurs dépendances **directes**, les sous-modules Git, les dépôts chargés par le client et les fonctions déclarées dans les sources. Les dépendances transitives des gestionnaires de paquets et le comportement runtime seront examinés pendant les audits.

## Inventaires par composant

| Composant | Inventaire | Référence examinée | Couverture |
| --- | --- | --- | --- |
| TeamServer C++ | [TeamServer](teamserver-inventory.md) | `C2TeamServer` `3d7a6e6` | 14 groupes de fonctions, 23 RPC, dépendances Conan, 6 sous-modules |
| Client Python | [Client](client-python-inventory.md) | Même dépôt | 17 groupes de fonctions, dépendances `pip`, 7 dépôts de modules configurés |
| Code partagé C++ | [C2Core](core-inventory.md) | `core/` `331f441` dans TeamServer | 45 modules, 7 commandes communes, beacons/listeners, contrats partagés |
| Implant Windows | [C2Implant](c2implant-windows-inventory.md) | `master` `8a0137a` | 10 sous-modules, dépendances, beacons EXE/DLL, build x86/x64/ARM64 |
| Implant Linux | [C2LinuxImplant](c2implant-linux-inventory.md) | `master` `17bfe61` | 6 sous-modules, dépendances, beacons/modules Linux x64, dummy SMB |
| Dépendances complémentaires | [Complément](remaining-dependencies-inventory.md) | Manifestes, lock Conan, workflows et réponses du propriétaire | Sous-module imbriqué, services tiers, paquets transitifs verrouillés et outils de build |
| Alignement des versions | [Comparaison](dependency-version-alignment.md) | Même références de parents | Matrice des commits partagés, Conan, pip et étapes nécessaires avant l'audit des usages |
| Mises à jour externes | [Relevé Conan/pip](external-dependency-updates.md) | Catalogues Conan Center et PyPI du 24 octobre 2026 | Versions publiées, contraintes résolues et ordre de mise à jour proposé |
| Publication des sous-modules | [Procédure de validation](submodule-release-policy.md) | Versions alignées des trois parents | Contrôle des gitlinks, builds et ordre de publication |

## Dépôts et maintenance

| Dépôt ou famille | Relation | Maintenance communiquée | Où le suivre |
| --- | --- | --- | --- |
| [C2TeamServer](https://github.com/maxDcb/C2TeamServer) | Parent TeamServer, client, protocole et packaging | Toi | TeamServer, Client |
| [C2Core](https://github.com/maxDcb/C2Core) | Sous-module partagé des trois parents C++ | Toi | C2Core |
| [C2Implant](https://github.com/maxDcb/C2Implant) | Parent Windows, releases importées | Toi | Implant Windows |
| [C2LinuxImplant](https://github.com/maxDcb/C2LinuxImplant) | Parent Linux, releases importées | Toi | Implant Linux |
| [Dnscommunication](https://github.com/maxDcb/Dnscommunication) | Sous-module DNS | Toi | TeamServer et implants |
| [libSocketHandler](https://github.com/maxDcb/libSocketHandler) | Sous-module TCP | Toi | TeamServer et implants |
| [libSocks5](https://github.com/maxDcb/libSocks5) | Sous-module SOCKS | Toi | TeamServer et implants |
| [libPipeHandler](https://github.com/maxDcb/libPipeHandler) | Sous-module SMB Windows | Toi | Implant Windows |
| [donut](https://github.com/maxDcb/donut) | Sous-module des parents C++, dépendance Python du client | Ton fork avec des mises à jour propres | TeamServer, Client et implants |
| [MemoryModule](https://github.com/maxDcb/MemoryModule) | Sous-module Windows | Ton fork | Implant Windows |
| [COFFLoader](https://github.com/maxDcb/COFFLoader) | Sous-module Windows | Ton fork ; écart amont à mesurer | Implant Windows |
| [COFFPacker](https://github.com/maxDcb/COFFPacker) | Sous-module Windows | Ton dépôt | Implant Windows |
| [agent-core](https://github.com/maxDcb/agent-core) | Dépendance Python de l'assistant | Toi | Client |
| [PeDropper](https://github.com/maxDcb/PeDropper), [PowershellWebDelivery](https://github.com/maxDcb/PowershellWebDelivery), [PeInjectorSyscall](https://github.com/maxDcb/PeInjectorSyscall), [ElfDropper](https://github.com/maxDcb/ElfDropper), [EarlyCascade](https://github.com/maxDcb/EarlyCascade) | Cinq dépôts de `DropperModules.conf` | Tu maintiens ces dépôts | Client |
| [GoDroplets](https://github.com/almounah/GoDroplets) | Sixième dépôt de `DropperModules.conf` | Tu maintiens son intégration et la version utilisée, pas le dépôt | Client |
| [DreamWalkers](https://github.com/maxDcb/DreamWalkers) | Dépôt de `ShellCodeModules.conf` | Toi | Client |
| [cpp-base64](https://github.com/ReneNyffenegger/cpp-base64) | Sous-module des trois parents C++ | Bibliothèque tierce standard | TeamServer et implants |

## Autres dépendances et surfaces

| Surface | Cataloguée où | Limite du catalogue actuel |
| --- | --- | --- |
| Paquets C++ Conan et bibliothèques système | TeamServer, deux implants et [complément](remaining-dependencies-inventory.md) | Dépendances directes et références additionnelles du lock TeamServer relevées ; provenance de chaque transitive et locks des implants non détaillés |
| Paquets Python `pip` | Client | Déclarations directes relevées ; transitives non détaillées |
| Protocole gRPC/Protobuf | TeamServer et Client | 23 RPC recensés ; chaque message et champ ne possède pas encore de fiche individuelle |
| `protocol/`, `packaging/`, `certs/`, `integration/` | TeamServer et contrats de release | Rôles relevés ; inventaires détaillés indépendants non réalisés |
| GitHub | TeamServer/Client/Implants | [Transport audité](github-transport-audit.md) ; conservé derrière `C2_ENABLE_GITHUB_TRANSPORT=OFF`, non prêt à être activé |
| OpenAI/Azure OpenAI | TeamServer/Client | Services externes recensés ; disponibilité et configuration runtime non auditées |
| Outils, scripts et artefacts de runtime | TeamServer/Client, C2Core | Emplacements et consommateurs recensés ; contenu concret dépend du build ou déploiement |

## État avant l'audit

Le **catalogue des composants principaux et de leurs dépendances directes est établi**. Les audits pourront partir des identifiants `TS`, `CL`, `CORE`, `M`, `WIN` et `LNX`. Pour une nomenclature exhaustive de tout le logiciel, il faudra encore détailler les dépendances transitives, les champs du protocole, les scripts de packaging/intégration et les fonctions propres à chaque dépôt externe maintenu. Ces travaux sont distincts de l'audit d'implémentation des éléments déjà listés.
