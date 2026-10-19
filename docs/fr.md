# CrowdSec

[CrowdSec](https://www.crowdsec.net/) lit les journaux de vos serveurs (SSH,
serveur web, Home Assistant, Nextcloud…), reconnaît les attaques grâce à ses
scénarios (force brute, scans, exploits) et **bannit** les adresses attaquantes
par ses bouncers (pare-feu, reverse proxy). Il partage aussi ce qu'il voit :
chaque installation reçoit la **liste de blocage de la communauté**. Cette
intégration amène CrowdSec dans Gladys : un appareil « CrowdSec » avec les
décisions actives et les alertes du jour, des scènes qui se déclenchent à chaque
nouveau bannissement ou nouvelle alerte (pour vous envoyer une notification avec
l'adresse et le scénario), une action qui débannit une adresse, et un widget de
tableau de bord avec les dernières adresses bannies.

Testée contre un vrai CrowdSec v1.8.1 (Docker, force brute SSH rejouée depuis
un fichier de journal, décisions ajoutées et supprimées avec `cscli`).
Développée sans installation en production ni sa liste de la communauté : vos
retours sont les bienvenus sur
[les issues](https://github.com/guim31/gladys-crowdsec/issues).

## Ce qu'il faut

- Gladys Assistant 5.1.0 ou plus récent.
- CrowdSec 1.5 ou plus récent, avec son **API locale** (LAPI, port 8080)
  joignable depuis la machine de Gladys. Une installation native n'écoute que
  sur `127.0.0.1:8080` : réglez `listen_uri: 0.0.0.0:8080` sous `api.server`
  dans `/etc/crowdsec/config.yaml` (et gardez le port 8080 fermé vers
  internet). L'image Docker écoute déjà sur toutes les interfaces : publiez son
  port 8080.
- Une **clé de bouncer** (accès en lecture seule aux décisions).
- Facultatif : un **compte machine** (identifiant et mot de passe) pour lire
  les alertes et débannir une adresse.

L'intégration lit le flux de décisions de sa clé de bouncer : la liste complète
au démarrage et une fois par heure, seulement les changements le reste du temps
(toutes les minutes par défaut). Avec un compte machine, elle lit aussi les
alertes de la dernière heure. Rien ne part sur internet.

## Mise en route

### 1. Créer une clé de bouncer

Sur la machine de CrowdSec :

```bash
cscli bouncers add gladys
```

Avec Docker : `docker exec crowdsec cscli bouncers add gladys`. La clé n'est
affichée qu'une fois : copiez-la.

### 2. Créer un compte machine (facultatif)

Pour les alertes, le pays des attaquants et l'action de débannissement :

```bash
cscli machines add gladys --password 'un-long-mot-de-passe' -f /dev/null
```

`-f /dev/null` compte : sans lui, `cscli` écrit les nouveaux identifiants à la
place de ceux de l'agent CrowdSec local.

### 3. Configurer l'intégration

Dans Gladys, **Intégrations → CrowdSec → Configuration** :

- **Adresse de l'API locale** : `http://192.168.1.2:8080` (la machine de
  CrowdSec) ;
- **Clé de bouncer** : la clé de l'étape 1 ;
- **Identifiant machine** et **Mot de passe machine** : le compte de l'étape 2,
  ou vide ;
- **Suppression de décisions par les scènes** : désactivée par défaut, voir
  plus bas ;
- **Intervalle de rafraîchissement** : de 30 secondes à 5 minutes ;
- **Langue des noms** : noms des fonctionnalités et résultats de scène.

**Tester la connexion** résume ce que l'intégration lit.

### 4. Ajouter l'appareil

Dans l'onglet **Découverte**, ajoutez l'appareil « CrowdSec ». Le widget et les
déclencheurs de scène fonctionnent sans lui.

## L'appareil

L'appareil « CrowdSec » a ces fonctionnalités :

| Fonctionnalité                 | Signification                                                                    |
| ------------------------------ | -------------------------------------------------------------------------------- |
| **Joignable**                  | 1 quand l'API locale répond, 0 après deux lectures en échec de suite             |
| **Décisions locales**          | Décisions actives prises ici : scénarios de CrowdSec, `cscli`, la console        |
| **Décisions de la communauté** | Décisions actives de la liste de la communauté et des listes de blocage abonnées |
| **Alertes (24 h)**             | Alertes commencées dans les dernières 24 heures (compte machine seulement)       |
| **Dernier scénario**           | Scénario de la dernière alerte, ou de la dernière décision locale                |

Chaque nombre garde son historique, pour un graphique des attaques au fil des
semaines.

## Tableau de bord

Le widget **Décisions CrowdSec** montre les décisions locales actives, la liste
de la communauté et les alertes du jour, puis les dernières adresses bannies :
adresse ou plage, scénario et temps restant, une icône rouge pour un
bannissement, orange pour un captcha. **Actualiser** relit CrowdSec.

## Scènes

### Déclencheurs

- **Nouvelle décision locale** : CrowdSec bannit une adresse (ou lui demande un
  captcha). Le filtre ne garde que les bannissements ou que les captchas.
  Variables : l'adresse ou la plage, la portée (`Ip`, `Range`), la remédiation
  (`ban`, `captcha`), le scénario, l'origine (`crowdsec` pour un scénario,
  `cscli` pour une décision ajoutée à la main), la durée en minutes, et le pays
  de l'attaquant quand CrowdSec le connaît (compte machine et enrichissement
  GeoIP).
- **Nouvelle alerte** : un scénario se déclenche sur une source (compte machine
  seulement), avec ou sans décision (un scénario en mode simulation lève des
  alertes sans bannir). Variables : le scénario, l'adresse source, la portée,
  le pays, l'opérateur réseau, le nombre d'événements et de décisions prises.

Un scénario qui bannit déclenche les deux : choisissez-en un pour vos
notifications. Les décisions de la liste de la communauté ne déclenchent jamais
rien : elles arrivent par dizaines de milliers. Quand plus de 20 décisions ou
alertes arrivent en une lecture (un gros scan), seules les 20 dernières
déclenchent une scène.

### Actions

- **État de CrowdSec** : lit les compteurs pour les actions suivantes —
  joignable ou non, décisions locales et de la communauté, alertes des
  dernières 24 heures, dernière adresse bannie, dernier scénario — et une
  phrase toute prête comme « CrowdSec : 3 décision(s) locale(s), 15012
  décision(s) de la communauté, 5 alerte(s) en 24 h (203.0.113.7, ssh-bf). »
- **Supprimer une décision (débannir)** : supprime toutes les décisions sur une
  adresse (`203.0.113.7`) ou une plage (`203.0.113.0/24`), y compris celles de
  la liste de la communauté (elles reviennent à la prochaine récupération de la
  liste). Une plage supprime les décisions qu'elle contient ; un bannissement sur une plage entière qui contient l'adresse reste en place. Le champ d'adresse accepte les variables du déclencheur.
  **Désactivée par défaut** : activez « Suppression de décisions par les
  scènes » dans la configuration, avec un compte machine. Sorties : le nombre
  de décisions supprimées et une phrase.

### Idées de scènes

- **Nouvelle décision locale** → envoyer un message : « CrowdSec a banni
  {{triggerEvent.data.ip}} ({{triggerEvent.data.scenario}}, {{triggerEvent.data.country}}) ».
- Chaque matin, **État de CrowdSec** → envoyer sa phrase : la nuit de vos
  serveurs en une ligne.
- Quand la fonctionnalité **Joignable** passe à 0, envoyer un message : la
  protection de la maison est tombée.
- Un bouton du tableau de bord qui lance **Supprimer une décision (débannir)**
  sur l'adresse d'un proche banni par erreur.

## Dépannage

- **« CrowdSec ne répond pas »** : vérifiez l'adresse et le port depuis la
  machine de Gladys (`curl http://192.168.1.2:8080/health` répond
  `{"status":"up"}`), et le `listen_uri` d'une installation native.
- **« clé de bouncer refusée »** : la clé est mal recopiée ou supprimée
  (`cscli bouncers list`) ; créez-en une nouvelle.
- **« identifiant ou mot de passe machine refusé : pas d'alertes »** : vérifiez
  avec `cscli machines list` que la machine existe et est validée. Les
  décisions restent lues.
- **« pas d'API locale CrowdSec à cette adresse »** : l'adresse mène à un autre
  service ; l'API locale répond sur le port 8080 par défaut.
- **« certificat refusé »** : utilisez l'adresse `http://` sur le réseau local,
  ou un certificat reconnu par Gladys.
- **Pas de pays dans les variables** : CrowdSec ajoute le pays avec le parser
  `crowdsecurity/geoip-enrich`, et seulement aux alertes : il faut le compte
  machine.
- Plus de détails dans les logs de l'intégration (Intégrations → CrowdSec →
  Logs). Les adresses complètes n'y figurent qu'avec `LOG_LEVEL=debug`.

## Limites

- Une seule API locale CrowdSec par intégration.
- Les décisions sur un pays ou un AS (portées autres que `Ip` et `Range`) ne
  sont pas comptées : le flux d'un bouncer ne porte que des adresses et des
  plages.
- Les alertes demandent un compte machine : avec la seule clé de bouncer, ni
  alertes ni pays.
- Ajouter une décision (bannir une adresse) n'est pas proposé : CrowdSec et
  `cscli` le font mieux.
- La console CrowdSec (app.crowdsec.net) n'est pas lue.
