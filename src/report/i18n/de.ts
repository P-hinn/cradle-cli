import type { Strings } from './strings.js'

/**
 * German.
 *
 * The terminology follows the German text of Regulation (EU) 2024/2847 rather
 * than a literal translation of the English wording, because a German reader
 * holding the regulation should find the same words in both. In particular:
 *
 * - **Schwachstelle**, not "Verwundbarkeit" — the term Art. 14 uses.
 * - **Unterstützungszeitraum**, not "Stützzeitraum" or "Supportzeitraum" — the
 *   term Art. 13(8) uses for the support period.
 * - **Komponente** and **Begründung** throughout, matching TR-03183-2 and the
 *   OpenVEX justification vocabulary respectively.
 * - **Abhängigkeit** for dependency, **Auflösung** for resolution.
 *
 * Where English uses a noun phrase as a column heading, German does too; where
 * English hedges ("says nothing about"), German hedges just as hard. Softening a
 * caveat in translation would make the German report claim more than the English
 * one, which is the one mistake a translation here must not make.
 */
export const de: Strings = {
  htmlLang: 'de',

  report: {
    title: (project, version) => `${project} ${version} — cradle-Bericht`,
    eyebrow: 'Software-Stückliste und Schwachstellenbericht',
    scanned: 'Geprüft am',
    packageManager: 'Paketmanager',
    scope: 'Umfang',
    scopeAll: 'Alle Abhängigkeiten',
    scopeProduction: 'Nur Produktion',
    components: 'Komponenten',
    workspaces: 'Workspaces',
    sbomFormat: 'SBOM-Format',
    sbomSerial: 'SBOM-Seriennummer',
    generatedBy: 'Erzeugt von',
    offlineBanner: {
      lead: 'Offline geprüft.',
      body: 'Die Komponentenliste ist vollständig, es wurde aber keine Schwachstellenabfrage durchgeführt. Dieser Bericht sagt nichts über bekannte Schwachstellen in diesen Komponenten aus.',
    },
  },

  summary: {
    heading: 'Überblick',
    componentsDetail: (direct, transitive) => `${direct} direkt · ${transitive} transitiv`,
    findings: 'Findings',
    findingsNotChecked: 'nicht geprüft (offline)',
    findingsAllFixable: 'für alle gibt es eine Behebung',
    findingsWithoutFix: (count) =>
      count === 1 ? '1 ohne verfügbare Behebung' : `${count} ohne verfügbare Behebung`,
    licences: 'Lizenzen',
    licencesAllDeclared: 'alle Komponenten geben eine an',
    licencesUndeclared: (count) => `${count} ohne Angabe`,
    suppressed: 'Unterdrückt',
    suppressedDetail: 'durch ein VEX-Statement ausgeschlossen',
    noVulnerabilities: 'Keine bekannten Schwachstellen in den geprüften Komponenten.',
  },

  nextSteps: {
    heading: 'Nächste Schritte',
    caption: 'die Updates, die am meisten erledigen',
    package: 'Paket',
    from: 'Von',
    to: 'Auf',
    clears: 'Erledigt',
    worst: 'Schwerste',
  },

  licences: {
    heading: 'Lizenzen',
    distinct: (count) => (count === 1 ? '1 verschiedene' : `${count} verschiedene`),
    licence: 'Lizenz',
    components: 'Komponenten',
    undeclared: 'nicht angegeben',
  },

  findings: {
    heading: 'Findings',
    offline:
      'Es wurde keine Schwachstellenabfrage durchgeführt, weil der Scan mit <code>--offline</code> lief. Ohne diese Option erneut ausführen, um diesen Abschnitt zu füllen.',
    none: 'Zum Zeitpunkt des Scans waren für diese Komponenten keine Schwachstellen bekannt. Das ist eine Momentaufnahme, keine Zusicherung — Advisories werden laufend veröffentlicht.',
    filterPlaceholder: 'Nach Paket, ID oder Beschreibung filtern',
    filterLabel: 'Findings filtern',
    noFix: 'keine Behebung',
    severity: 'Schwere',
    advisory: 'Advisory',
    package: 'Paket',
    fixedIn: 'Behoben in',
    details: 'Details',
    summary: 'Beschreibung',
    pulledInBy: 'Eingebunden über',
    published: 'Veröffentlicht',
    updated: 'Aktualisiert',
    references: 'Quellen',
    severityFromCvss: (severity, version, score, vector) =>
      `${severity} — CVSS v${version} Basiswert ${score} <code>${vector}</code>. Das bewertet die Schwachstelle abstrakt, nicht ihre Ausnutzbarkeit in diesem Projekt.`,
    severityFromDatabase: (severity) =>
      `${severity} — wie von der Advisory-Datenbank bewertet. Es wurde kein CVSS-Vektor veröffentlicht, den dieses Werkzeug berechnen kann.`,
    severityUnknown:
      'unbekannt — das Advisory enthält weder einen berechenbaren CVSS-Vektor noch eine Schwere-Einstufung.',
    exploited: 'Ausnutzung',
    knownExploited: 'in CISA KEV',
    knownExploitedSince: (date) => `in CISA KEV seit ${date}`,
    epss: (percent, percentile) => `EPSS ${percent}, ${percentile}. Perzentil`,
    noExploitData: 'keine Daten',
    exploitCaption:
      'Ob die Schwachstelle offenbar ausgenutzt wird — eine andere Frage als die, wie schwer sie wäre. CISA KEV ist ein Nachweis tatsächlicher Ausnutzung; EPSS ist eine tägliche Schätzung der Wahrscheinlichkeit für die nächsten 30 Tage. Beide sind über die CVE geschlüsselt, ein Advisory ohne CVE zeigt daher „keine Daten“ — was nicht dasselbe ist wie kein Risiko.',
    exploitUnavailable: (sources) =>
      `Diese Spalte ist unvollständig: ${sources} war während des Scans nicht erreichbar.`,
  },

  readiness: {
    heading: 'CRA-Bereitschaft',
    caption:
      'Der Cyber Resilience Act verlangt Dokumentation und Prozesse, nicht nur einen sauberen Abhängigkeitsbaum — und genau das wird vergessen. Wo cradle es nicht wissen kann, sagt es das, statt zu raten. Nichts davon ist eine Konformitätsbewertung.',
    nothingOutstanding: 'Nichts offen, soweit cradle es sehen kann.',
    needAttention: (open, total) =>
      open === 1
        ? `1 von ${total} braucht Aufmerksamkeit.`
        : `${open} von ${total} brauchen Aufmerksamkeit.`,
    status: 'Status',
    check: 'Prüfpunkt',
    findingAndNextStep: 'Befund und nächster Schritt',
    next: 'Nächster Schritt:',
  },

  profile: {
    caption: (title, version, date) => `${title} Version ${version}, Stand ${date}.`,
    notAConformityAssessment:
      'Dies vergleicht die Datenfelder der nebenstehenden SBOM mit denen, die die Richtlinie auflistet. Es ist <strong>keine Konformitätsbewertung</strong>, und mehrere Anforderungen der Richtlinie betreffen Ihren Build-Prozess statt dieser Datei. Wo cradle eine Antwort nicht kennen kann, sagt es das, statt zu raten.',
    status: 'Status',
    dataField: 'Datenfeld',
    askedFor: 'Verlangt als',
    detail: 'Befund',
    statusLabel: {
      met: 'Erfüllt',
      partial: 'Teilweise',
      open: 'Offen',
      'not-assessable': 'Nicht prüfbar',
    },
    requirement: { required: 'Pflicht', additional: 'zusätzlich', optional: 'optional' },
  },

  suppressed: {
    heading: 'Unterdrückt',
    caption:
      'Diese Findings zählen oben nicht mit, weil ein VEX-Statement in diesem Repository sie ausschließt. Die Kategorie ist der prüfbare Teil, der Hinweis die Begründung.',
    justification: 'Begründung',
    expires: 'Läuft ab',
    noExpiry: 'kein Ablauf',
    lapsed: 'abgelaufen',
    inDays: (days) => (days === 0 ? 'heute' : days === 1 ? 'in 1 Tag' : `in ${days} Tagen`),
  },

  notes: {
    heading: 'Hinweise zur Auflösung',
    caption:
      'Formen in der Lockfile, die eine SBOM nicht exakt ausdrücken kann. Keine davon ist ein Fehler, und keine wird verschwiegen: eine stillschweigend ausgelassene Abhängigkeit ließe die Zahlen oben vollständig aussehen, ohne es zu sein.',
    what: 'Was',
    package: 'Paket',
    detail: 'Befund',
    label: {
      'git-dependency': 'Aus git installiert',
      'local-dependency': 'Aus einem lokalen Pfad installiert',
      'aliased-dependency': 'Unter anderem Namen installiert',
      'patched-dependency': 'Vom Paketmanager gepatcht',
      'unresolved-dependency': 'Deklariert, aber nicht in der Lockfile',
      'bundled-dependency': 'Im übergeordneten Paket enthalten',
    },
  },

  components: {
    heading: 'Komponenten',
    none: 'Es wurden keine Abhängigkeiten aufgelöst.',
    filterPlaceholder: 'Nach Name, Version oder Lizenz filtern',
    filterLabel: 'Komponenten filtern',
    directOnly: 'nur direkte',
    undeclaredLicence: 'Lizenz nicht angegeben',
    name: 'Name',
    version: 'Version',
    licence: 'Lizenz',
    relationship: 'Beziehung',
    direct: 'direkt',
    transitive: 'transitiv',
    workspace: 'Workspace',
    dev: 'dev',
  },

  colophon: {
    disclaimerLead: 'Dies ist eine technische Momentaufnahme, keine Rechtsberatung.',
    disclaimerBody: (tool) =>
      `${tool} dokumentiert, welche Komponenten ein Projekt ausliefert und welche Advisories zum Zeitpunkt des Scans dazu öffentlich waren. Es ist keine Konformitätsbewertung, keine Konformitätserklärung, und es bescheinigt die Einhaltung keiner Verordnung.`,
    advisorySnapshot: (timestamp) =>
      `Die Findings geben den Stand der von OSV.dev zusammengeführten Advisory-Datenbanken zum ${timestamp} wieder. Advisories werden laufend veröffentlicht; ein leeres Ergebnis heißt „damals war nichts bekannt“, nicht „es existiert nichts“.`,
    embeddedData:
      'Die maschinenlesbaren Daten hinter dieser Seite sind in ihr eingebettet, im <code>application/json</code>-Block weiter unten, zusätzlich zur CycloneDX-SBOM neben dieser Datei.',
  },

  severity: {
    critical: 'kritisch',
    high: 'hoch',
    medium: 'mittel',
    low: 'niedrig',
    none: 'keine',
    unknown: 'unbekannt',
  },

  readinessStatus: {
    met: 'erfüllt',
    partial: 'teilweise',
    open: 'offen',
    'not-assessable': 'nicht prüfbar',
  },

  markdown: {
    verdictFailing: (count, gate) =>
      `❌ ${count} ${count === 1 ? 'neues Finding' : 'neue Findings'} ${gate}`,
    thresholdSeverity: (severity) => `ab Schwere ${severity}`,
    thresholdKev: 'nachweislich ausgenutzt',
    thresholdEpss: (percent) => `EPSS ab ${percent}`,
    thresholdJoin: (parts) =>
      parts.length <= 1
        ? (parts[0] ?? '')
        : `${parts.slice(0, -1).join(', ')} oder ${parts.at(-1)}`,
    verdictNewBelowThreshold: (count) =>
      `⚠️ ${count} ${count === 1 ? 'neues Finding' : 'neue Findings'}, keines über der Schwelle`,
    verdictClean: '✅ Nichts Neues seit der Baseline',
    subtitle: (components, manager, scope) => `${components} Komponenten · ${manager} · ${scope}`,
    scopeAll: 'alle Abhängigkeiten',
    scopeProduction: 'nur Produktion',
    knownFindings: (count) =>
      `**${count}** ${count === 1 ? 'bekanntes Finding' : 'bekannte Findings'}`,
    newSinceBaseline: (count) => `**${count}** neu seit der Baseline`,
    ruledOutByVex: (count) => `**${count}** per VEX ausgeschlossen`,
    noBaselineYet: '_noch keine Baseline, daher zählt alles als neu_',
    severity: 'Schwere',
    advisory: 'Advisory',
    package: 'Paket',
    fixedIn: 'Behoben in',
    noFixYet: '— _noch keine Behebung_',
    truncated: (count) =>
      `_${count} ${count === 1 ? 'weiteres neues Finding steht' : 'weitere neue Findings stehen'} im Bericht._`,
    resolved: (count) =>
      `${count} ${count === 1 ? 'Finding aus der Baseline ist' : 'Findings aus der Baseline sind'} erledigt. \`cradle check --baseline\` räumt die Datei auf.`,
    unfixableSummary: (count) => `Für ${count} der neuen Findings gibt es keine Behebung`,
    unfixableBody:
      'Die brauchen eine Entscheidung statt eines Updates. `cradle suppress <id> --justification ' +
      '<kategorie>` hält eine in `.cradle/vex.json` fest, wo ein Prüfer sie sehen und ihr ' +
      'widersprechen kann.',
    artifact: (name) =>
      `Der vollständige Bericht, die SBOM und \`findings.json\` hängen als **${name}** an diesem Lauf.`,
    footer: (tool, version) =>
      `${tool} ${version} — eine technische Momentaufnahme, keine Rechtsberatung und keine Konformitätsbewertung.`,
  },
}
