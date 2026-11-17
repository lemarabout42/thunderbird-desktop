# Windows Hello et coffre de profil

Ce fork Windows expérimental ouvre un **profil de test complet dans un système
de fichiers chiffré**. Le code du coffre est intégré au point d'entrée de
Thunderbird ; la compilation complète et sa validation restent en cours.
La primitive AES-GCM du premier prototype ne sert pas au stockage du profil.

Base Thunderbird : `ada7ac0ab6ee12982315d628bb0c6f55b19b0096`.
Base Gecko de compilation : `d7161e35da7704cff60e48ee86fb7747ffcc93c7`.
Ce travail n'est ni une version officielle de Thunderbird ni un audit de sécurité
indépendant du nouveau coffre.

## Utilisation de la version de test

- Windows Hello doit être configuré dans les options de connexion Windows.
  Windows choisit l'empreinte, le visage ou le PIN ; le fork ne reçoit jamais
  ces données et ne promet pas un mode « empreinte uniquement ».
- Installer `vault-runtime/Dokan_x64.msi` en suivant son assistant et la demande
  Windows d'autorisation administrateur. Redémarrer si l'assistant le demande.
  Le script de préparation ne procède pas à cette installation.
- Garder le dossier `vault-runtime` à côté de `thunderbird.exe`.
- Libérer la lettre **Z:** et fermer toute autre instance de cppcryptfs.
- Le premier démarrage crée un coffre séparé sous
  `%LOCALAPPDATA%\ThunderbirdHello\TestProfile-v2\vault`. Plusieurs validations
  Hello peuvent être nécessaires pour créer la protection et l'ouvrir.
- Conserver les 64 caractères de récupération sur papier ou dans un lieu sûr
  hors de ce PC, puis les saisir pour vérifier la copie. Cette clé ouvre le
  coffre sans Hello. L'application ne l'enregistre pas automatiquement en clair.
  Une copie en clair ou une capture de cette clé sur le même PC permettrait
  de contourner la protection du coffre : n'en conserver aucune.
- Les lancements suivants demandent Hello avant d'ouvrir le profil. Une
  annulation ferme le programme. Fermer Thunderbird retire le lecteur Z: ; si
  une application garde un fichier ouvert, la fermeture demande de le libérer.

Aucun profil Thunderbird existant n'est migré. Commencer avec des données de
test ; les paramètres et messages d'un autre profil ne sont pas modifiés.
Ne pas déplacer les répertoires de comptes ou les caches hors du lecteur chiffré.
La lettre Z: est fixe car Thunderbird peut conserver des chemins absolus.

## Chiffrement et clés

Le moteur est [cppcryptfs v1.4.5.2](https://github.com/bailey27/cppcryptfs/tree/v1.4.5.2),
avec [Dokan 2.3.1.1000](https://github.com/dokan-dev/dokany/tree/v2.3.1.1000).
Les contenus et noms de fichiers sont chiffrés à la volée dans le format
compatible gocryptfs. Le mode créé utilise les options amont par défaut, dont
`HKDF`, `GCMIV128` et les noms chiffrés ; `scryptn=17` est demandé explicitement.
Il n'y a pas de copie complète temporaire du profil en clair.

Un secret aléatoire de 32 octets, représenté par 64 caractères hexadécimaux,
protège la clé maîtresse du système de fichiers. Le secret est transmis au
client signé par son entrée standard, jamais dans les arguments, l'environnement
ou un fichier temporaire. La sortie des outils est vidée sans journalisation.
Le secret de l'application est effacé après montage ; le moteur conserve les
clés nécessaires pendant que le lecteur est ouvert.

Le secret est enveloppé par une clé RSA-2048 privée non exportable dans le
fournisseur Microsoft Passport. Cette clé autorise signature et déchiffrement.
La variante versionnée utilise PKCS#1 v1.5 : le fournisseur présent sur le PC de
test a refusé OAEP lors de l'opération privée. Le chiffrement public est suivi
d'une signature SHA-256/PKCS#1 par la même clé Passport. Cette signature couvre
un domaine fixe, l'identifiant du protecteur et le texte chiffré ; elle est
vérifiée avec BCrypt **avant** toute demande de déchiffrement privé. Cela empêche
la substitution d'un secret choisi au moyen de la seule clé publique.
Le format v2 de `hello.key` contient 552 octets ; les enveloppes v1 non signées
du prototype sont rejetées. La signature n'est jamais utilisée comme clé AES.

Le fournisseur doit conserver une politique exigeant un nouveau geste Hello ;
les usages et la politique d'export sont vérifiés à chaque ouverture. Le test
matériel vérifie qu'un déchiffrement silencieux est refusé, même après un geste
réussi. Les propriétés `NgcCacheType` et `PinCacheIsGestureRequired` ne sont pas
un contrat public documenté de CNG : une propriété absente ou inattendue bloque
l'ouverture. Aucune substitution par DPAPI, par une simple boîte de consentement
ou par un fournisseur logiciel n'est prévue. Le fork ne réalise pas
d'attestation et ne garantit donc pas à lui seul la présence d'un TPM.

## Démarrage, fermeture et récupération

`ProfileVaultSession` est ouvert par le processus parent de `thunderbird.exe`
après l'installation du blocage des DLL et avant XPCOM. Le coffre est créé dans
un répertoire transactionnel, puis renommé une fois la récupération confirmée.
Un verrou de fichier empêche deux sessions d'ouvrir le même coffre.

Les exécutables du moteur et leur DLL sont vérifiés par SHA-256 avant tout
transfert de secret. L'application refuse une instance cppcryptfs préexistante,
crée la sienne suspendue, l'attache à un job Windows avec terminaison à la
fermeture, puis vérifie l'identité du serveur du canal nommé et sa disponibilité.
Le moteur interdit les autres sessions et les services pour ce montage.

Le profil itinérant et le profil local sont tous deux fixés à `Z:\Profile` ;
`TEMP` et `TMP` pointent vers `Z:\Temp`. Les variables de redémarrage Gecko
susceptibles de choisir un autre profil sont réinitialisées. Les arguments
permettant de changer de profil, de lancer une autre application XUL ou une
tâche d'arrière-plan sont refusés par cette version de test.

Après l'arrêt de Gecko et la libération du profil, le lecteur est démonté.
La fermeture brutale du parent ferme son job et termine uniquement son moteur,
ce qui fait retirer le lecteur par Dokan. Cette protection limite l'exposition
du montage après un crash ; elle ne remplace pas les sauvegardes et ne garantit
pas que la dernière écriture survive à une coupure de courant.

Une clé Passport manquante n'est jamais remplacée silencieusement. La
récupération demande le code conservé hors du PC et crée un nouveau protecteur.
Le code doit d'abord réussir à monter le système de fichiers et à lire son
identifiant interne chiffré. Ce n'est qu'après cette vérification que
`hello.key` est remplacé de façon atomique. Le secret du système de fichiers
et les messages restent les mêmes. Sans Hello utilisable **et** sans code de
récupération, le fork n'offre pas de moyen de retrouver les données.

## Périmètre de protection

| Chemin | Comportement |
| --- | --- |
| Parent Thunderbird, ouverture du profil de test | Hello puis montage avant XPCOM |
| Annulation Hello | Sortie sans profil ouvert |
| Processus enfants | Démarrage IPC habituel, pas de nouvelle demande Hello |
| Autre programme, coffre fermé | Fichiers chiffrés, sans clé de montage |
| Autre programme de la même session, coffre ouvert | Accès possible au lecteur en clair |
| Mise en veille, verrouillage Windows, inactivité | Pas de fermeture automatique du coffre |
| Updater et crash reporter | Désactivés dans la configuration de test |
| Export ou pièce jointe enregistrée ailleurs par l'utilisateur | Hors du coffre |
| Compilation avec `--disable-windows-hello-lock` | Fonctionnement Thunderbird amont, sans ce coffre |

Les tailles, dates, nombres de fichiers et la configuration du coffre restent
des métadonnées observables. Le format n'empêche pas un retour à une ancienne
copie complète du coffre. Un administrateur, un programme malveillant pendant
l'utilisation, un exécutable Thunderbird remplacé, la mémoire, le fichier
d'échange et l'hibernation restent hors de la garantie de ce prototype. Le
chiffrement du profil ne remplace pas le chiffrement du disque Windows.

## Préparation et vérification

`tools/windows-hello/prepare-runtime.ps1 -Destination <dossier>/vault-runtime`
prépare les dépendances officielles épinglées, contrôle leur SHA-256 et leur
signature Authenticode, et joint licences et provenance. Il ne modifie pas
la configuration de sécurité Windows et n'installe pas le pilote.

La compilation se fait dans la racine Gecko avec `comm/` lié à ce dépôt,
`ac_add_options --enable-application=comm/mail` et les outils Mozilla pour
Windows. L'option Hello est activée par défaut sur Windows. Une compilation
sans coffre s'obtient par `ac_add_options --disable-windows-hello-lock`.
Le paquet de test doit inclure le runtime à côté de l'exécutable.

Les tests natifs s'exécutent avec
`tools/windows-hello/run-native-tests.ps1` depuis un environnement Visual Studio,
ou avec `-ZigPath <zig.exe>` pour Zig 0.15.2. Les tests automatiques n'ouvrent
aucun profil personnel et ne demandent aucune empreinte. Les outils manuels
`HelloProbe` et `VaultProbe` ouvrent des demandes Windows Hello et doivent être
annoncés avant exécution.

Validation effectuée au 17 novembre 2026 :

- Compilation et suite native réussies avec MSVC (`/W4 /WX`) et Zig C++17
  (`-Wall -Wextra -Werror`), avec le vrai SDK Windows pour la variante MSVC.
- 28 scénarios du verrou initial avec frontière Windows simulée.
- AES-GCM du prototype : vecteur indépendant, altérations, troncatures,
  mauvaises clés/contextes, bornes et effacement, avec le vrai CNG Windows.
- Formats d'enveloppe et récupération, arguments de profil, échappement Windows,
  Unicode, transfert stdin, délais d'attente et erreurs des processus.
- Sur le matériel Windows Hello : enveloppe v2 signée créée et déchiffrée,
  secret identique, déchiffrement silencieux bloqué, enveloppe altérée rejetée.
- Coffre natif v2 : création puis réouverture, mail factice et transaction
  SQLite/WAL écrits et relus, démontage réussi ; absence des textes et noms
  factices dans les fichiers chiffrés après fermeture. Configuration réellement
  créée : `EMENames`, `LongNames`, `DirIV`, `HKDF`, `Raw64`, `GCMIV128`,
  scrypt N=131072.
- Arrêt brutal du parent natif : retrait automatique du lecteur chiffré.
  Le test ne termine que le processus factice qu'il a lui-même créé.
- Arrêt brutal du moteur de fichiers seul : retrait du lecteur puis fermeture
  normale du parent, sans demande répétée de fermer un lecteur déjà disparu.
- Récupération interactive d'un nouveau coffre factice : conservation et
  confirmation du code, perte simulée de `hello.key`, récupération des messages
  et de SQLite, conservation de l'identité du coffre, nouveau protecteur, puis
  réouverture avec ce protecteur Hello. Aucun code n'a été capturé dans les logs.
- Confinement natif : les chemins de profil hérités sont remplacés, les
  variables de réinitialisation (y compris en minuscules) sont supprimées,
  le profil/cache et les répertoires temporaires restent sur Z: dans les
  environnements CRT et Win32, et les arguments fixent ce même profil.
- Compilation complète Thunderbird et lancement de l'application : en cours,
  pas encore validés.
- Configurations complètes avec et sans coffre : génération des deux backends
  réussie. `config.status` et `backend.mk` confirment que la définition et les
  sources Hello sont présentes dans le premier cas et absentes dans le second.

`VaultProbe` peut écrire une clé de récupération de **profil factice** dans un
fichier explicitement fourni par son opérateur, uniquement pour les essais
natifs reproductibles. Cette possibilité n'est pas exposée dans les arguments
ou l'environnement de Thunderbird. Ces fichiers de test ne doivent jamais être
confondus avec une stratégie de récupération des données personnelles.

## Rapport Hermès sur le premier prototype

L'audit fourni porte sur l'ancien verrou et la primitive AES-GCM, pas sur cette
nouvelle intégration. Le constat de stockage initial en clair était exact.
La nouvelle intégration doit être évaluée séparément ; son existence ne vaut
pas audit indépendant. La primitive AES-GCM initiale n'a toujours pas de budget
par clé et ne doit pas être utilisée comme backend de profil.

Le `KeyError` allégué pour `CONFIG["MOZ_THUNDERBIRD_HELLO_LOCK"]` désactivé ne
correspond pas à l'implémentation Mozilla : `ConfigEnvironment.substs` est
accessible au contexte via `ReadOnlyKeyedDefaultDict(config.substs.get)` ; une
clé absente retourne `None`. Ce comportement a été exécuté avec les classes
réelles de la révision Gecko, puis confirmé par la génération complète des deux
configurations sur Windows. Cela ne vaut pas compilation complète des deux
variantes : le build de la variante avec coffre reste en cours.
