// -----------------------------------------------------------------------------
// Texts the integration sends to Gladys outside the widget (src/widgets.js):
// connection status, errors, the "Test the connection" report, scene outputs.
// Four languages, the four of the Gladys interface; German says "du", Spanish
// "usted". test/i18n.test.js checks every table.
// -----------------------------------------------------------------------------

import { ERROR_KINDS } from './crowdsec/client.js';

export const INIT_FAILED = {
  en: 'Initialization failed, check the integration logs.',
  fr: "L'initialisation a échoué, consultez les logs de l'intégration.",
  de: 'Initialisierung fehlgeschlagen, sieh dir die Protokolle der Integration an.',
  es: 'La inicialización ha fallado, consulte los registros de la integración.',
};

export const CONNECTION_TEXT = {
  noUrl: {
    en: 'Enter the address of the CrowdSec Local API in the configuration.',
    fr: "Saisissez l'adresse de l'API locale de CrowdSec dans la configuration.",
    de: 'Gib die Adresse der lokalen CrowdSec-API in der Konfiguration ein.',
    es: 'Introduzca la dirección de la API local de CrowdSec en la configuración.',
  },
  invalidUrl: {
    en: 'Address not understood, e.g. http://192.168.1.2:8080',
    fr: 'Adresse incomprise, ex. http://192.168.1.2:8080',
    de: 'Adresse nicht verstanden, z. B. http://192.168.1.2:8080',
    es: 'Dirección no válida, p. ej. http://192.168.1.2:8080',
  },
  noKey: {
    en: 'Enter a bouncer key: cscli bouncers add gladys',
    fr: 'Saisissez une clé de bouncer : cscli bouncers add gladys',
    de: 'Gib einen Bouncer-Schlüssel ein: cscli bouncers add gladys',
    es: 'Introduzca una clave de bouncer: cscli bouncers add gladys',
  },
};

// One short explanation per error kind (src/crowdsec/client.js).
export const ERROR_TEXT = {
  [ERROR_KINDS.UNREACHABLE]: {
    en: 'CrowdSec does not answer',
    fr: 'CrowdSec ne répond pas',
    de: 'CrowdSec antwortet nicht',
    es: 'CrowdSec no responde',
  },
  [ERROR_KINDS.TLS]: {
    en: 'certificate refused: use an http:// address or a trusted certificate',
    fr: 'certificat refusé : utilisez une adresse http:// ou un certificat reconnu',
    de: 'Zertifikat abgelehnt: Nutze eine http://-Adresse oder ein vertrauenswürdiges Zertifikat',
    es: 'certificado rechazado: use una dirección http:// o un certificado reconocido',
  },
  [ERROR_KINDS.AUTH]: {
    en: 'bouncer key refused',
    fr: 'clé de bouncer refusée',
    de: 'Bouncer-Schlüssel abgelehnt',
    es: 'clave de bouncer rechazada',
  },
  [ERROR_KINDS.MACHINE_AUTH]: {
    en: 'machine login or password refused: no alerts',
    fr: 'identifiant ou mot de passe machine refusé : pas d’alertes',
    de: 'Maschinen-Login oder Passwort abgelehnt: keine Alarme',
    es: 'usuario o contraseña de máquina rechazados: sin alertas',
  },
  [ERROR_KINDS.NOT_CROWDSEC]: {
    en: 'no CrowdSec Local API at this address (port 8080?)',
    fr: "pas d'API locale CrowdSec à cette adresse (port 8080 ?)",
    de: 'keine lokale CrowdSec-API unter dieser Adresse (Port 8080?)',
    es: 'no hay API local de CrowdSec en esta dirección (¿puerto 8080?)',
  },
  [ERROR_KINDS.HTTP]: {
    en: 'unexpected answer, see the logs',
    fr: 'réponse inattendue, voir les logs',
    de: 'unerwartete Antwort, sieh in den Protokollen nach',
    es: 'respuesta inesperada, consulte los registros',
  },
};

// The "Test the connection" report and the sentences of the scene actions.
export const REPORT_TEXT = {
  en: {
    ok: 'Connected',
    local: (count) => `${count} local decision(s)`,
    community: (count) => `${count} community decision(s)`,
    alerts: (count) => `${count} alert(s) in 24 h`,
    noMachine: 'no machine account: no alerts',
    unreachable: 'CrowdSec does not answer',
  },
  fr: {
    ok: 'Connecté',
    local: (count) => `${count} décision(s) locale(s)`,
    community: (count) => `${count} décision(s) de la communauté`,
    alerts: (count) => `${count} alerte(s) en 24 h`,
    noMachine: "pas de compte machine : pas d'alertes",
    unreachable: 'CrowdSec ne répond pas',
  },
  de: {
    ok: 'Verbunden',
    local: (count) => `${count} lokale Entscheidung(en)`,
    community: (count) => `${count} Community-Entscheidung(en)`,
    alerts: (count) => `${count} Alarm(e) in 24 h`,
    noMachine: 'kein Maschinenkonto: keine Alarme',
    unreachable: 'CrowdSec antwortet nicht',
  },
  es: {
    ok: 'Conectado',
    local: (count) => `${count} decisión(es) local(es)`,
    community: (count) => `${count} decisión(es) de la comunidad`,
    alerts: (count) => `${count} alerta(s) en 24 h`,
    noMachine: 'sin cuenta de máquina: sin alertas',
    unreachable: 'CrowdSec no responde',
  },
};

// The `sentence` output of "Delete a decision".
export const UNBAN_TEXT = {
  en: { deleted: (count, value) => `${count} decision(s) deleted on ${value}` },
  fr: { deleted: (count, value) => `${count} décision(s) supprimée(s) sur ${value}` },
  de: { deleted: (count, value) => `${count} Entscheidung(en) für ${value} gelöscht` },
  es: { deleted: (count, value) => `${count} decisión(es) eliminada(s) en ${value}` },
};

export const ACTION_TEXT = {
  unbanDisabled: {
    en: 'Deleting decisions is disabled in the configuration of the integration.',
    fr: "La suppression de décisions est désactivée dans la configuration de l'intégration.",
    de: 'Das Löschen von Entscheidungen ist in der Konfiguration der Integration deaktiviert.',
    es: 'La eliminación de decisiones está desactivada en la configuración de la integración.',
  },
  noMachine: {
    en: 'Deleting a decision needs a machine account in the configuration.',
    fr: 'Supprimer une décision demande un compte machine dans la configuration.',
    de: 'Zum Löschen einer Entscheidung braucht es ein Maschinenkonto in der Konfiguration.',
    es: 'Eliminar una decisión requiere una cuenta de máquina en la configuración.',
  },
  badAddress: {
    en: 'Not an IP address or range, e.g. 203.0.113.7 or 203.0.113.0/24.',
    fr: 'Ce n’est pas une adresse IP ni une plage, ex. 203.0.113.7 ou 203.0.113.0/24.',
    de: 'Keine IP-Adresse und kein Bereich, z. B. 203.0.113.7 oder 203.0.113.0/24.',
    es: 'No es una dirección IP ni un rango, p. ej. 203.0.113.7 o 203.0.113.0/24.',
  },
};

export const LANGUAGE_FALLBACK = 'en';

/** "Name: text", with the space French puts before a colon. */
export const labelled = (name, text, language) =>
  `${name}${language === 'fr' ? ' : ' : ': '}${text}`;
export const pick = (text, language) => text[language] ?? text[LANGUAGE_FALLBACK];
