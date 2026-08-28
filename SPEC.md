# cradle — Spezifikation

Verbindliche Referenz für die Entwicklung. Enthält die ursprüngliche Spezifikation
des Maintainers, die daran vorgenommenen fachlichen Korrekturen und die getroffenen
Designentscheidungen. Bei Widerspruch gilt dieses Dokument.

- **npm-Paket:** `cradle-cli`
- **Binary:** `cradle`
- **Lizenz:** Apache-2.0
- **Stand:** 28.08.2026

---

## 1. Ziel und Abgrenzung

Der EU Cyber Resilience Act (Verordnung (EU) 2024/2847) verpflichtet Hersteller von
Produkten mit digitalen Elementen dazu, ihre Komponenten zu dokumentieren und
Schwachstellen zu behandeln. Für Container-Images gibt es dafür gutes Tooling
(Syft, Grype, Trivy). Für reine npm-/TypeScript-Projekte ist die Lage schlechter:
vorhandene Werkzeuge sind container-orientiert oder erzeugen ein SBOM, ohne bei dem
zu helfen, was Teams tatsächlich brauchen — einer wiederholbaren, im CI verankerten
Routine plus lesbarer Dokumentation für Audits.

`cradle` füllt diese Lücke. Der Anspruch ist ausdrücklich **nicht**, die technisch
vollständigste SBOM-Engine zu bauen, sondern die angenehmste Bedienung für
Node-Teams: ein Befehl, ein sinnvoller Default, ein Report, den man einem Auditor
oder Kunden schicken kann.

**Zielgruppe:** Entwicklungsteams in EU-Unternehmen, die Software kommerziell
ausliefern und in den nächsten Monaten CRA-Nachweise brauchen werden.

**Ehrliche Wettbewerbsthese:** `@cyclonedx/cyclonedx-npm` (v6, aktiv gepflegt)
erzeugt bereits saubere CycloneDX-SBOMs aus npm-Projekten. SBOM-Erzeugung ist
Tischeinsatz, kein Alleinstellungsmerkmal. Unser Unterschied ist alles, was danach
kommt: Findings mit Pfad im Abhängigkeitsbaum, VEX-Unterdrückung, Baseline-Diffing,
CRA-Readiness-Checkliste und der HTML-Report.

## 2. Leitprinzipien

Bei jeder Designentscheidung in dieser Reihenfolge:

1. **Ein Befehl muss reichen.** `npx cradle-cli` ohne jede Konfiguration muss in
   einem beliebigen npm-Projekt etwas Nützliches produzieren. Konfiguration ist
   optional und additiv, nie Voraussetzung.
2. **Ausgabe vor Features.** Der HTML-Report ist das Produkt. Wenn eine Funktion den
   Report nicht besser macht, kommt sie später.
3. **Keine Lügen über Rechtssicherheit.** Wir helfen bei Dokumentation und Prozess.
   Wir zertifizieren nichts. Nirgends im Produkt steht „CRA-konform".
4. **Offline-fähig, wo möglich.** SBOM-Erzeugung darf keinen Netzzugriff brauchen.
   Nur die Schwachstellenabfrage geht raus, und die ist abschaltbar.
5. **Keine Telemetrie. Nie.** Das ist ein Verkaufsargument, kein Verzicht.

---

## 3. Verifizierte CRA-Grundlagen

Alle Angaben gegen den Verordnungstext geprüft. Quellen am Ende des Dokuments.

### 3.1 Fristen (Art. 71)

| Datum | Was |
|---|---|
| 10.12.2024 | Inkrafttreten |
| 11.06.2026 | Kapitel IV (Art. 35–51): Notifizierung von Konformitätsbewertungsstellen |
| **11.09.2026** | **Art. 14: Meldepflichten** |
| **11.12.2027** | **Volle Anwendung** |

### 3.2 Meldepflicht (Art. 14) — dreistufig, nicht einstufig

Für **aktiv ausgenutzte Schwachstellen** und **schwerwiegende Sicherheitsvorfälle**:

1. Frühwarnung binnen **24 Stunden**
2. Schwachstellenmeldung binnen **72 Stunden**
3. Abschlussbericht binnen **14 Tagen** (bei Vorfällen: **1 Monat**)

Meldeweg: ENISA Single Reporting Platform **plus** das zuständige nationale CSIRT.
Formulierungen wie „24-Stunden-Meldepflicht an ENISA" sind verkürzt und gehören
nicht ins README.

### 3.3 SBOM-Umfang (Anhang I Teil II Nr. 1)

Verlangt wird eine SBOM „in einem gängigen maschinenlesbaren Format, die zumindest
die Abhängigkeiten der obersten Ebene erfasst".

Daraus folgt:

- **Transitive Abhängigkeiten sind rechtlich nicht Pflicht.** Wir erfassen sie
  trotzdem, weil Schwachstellentriage unter 24-Stunden-Druck ohne sie nicht
  funktioniert. Das ist unser Argument, nicht das des Gesetzgebers.
- Kein Format ist namentlich vorgeschrieben. CycloneDX und SPDX erfüllen beide
  „gängig und maschinenlesbar".
- Die SBOM ist Teil der technischen Dokumentation (Anhang VII), 10 Jahre
  aufzubewahren, Marktüberwachungsbehörden auf Anfrage vorzulegen.
- **Es gibt keine Veröffentlichungspflicht.**

### 3.4 Support-Zeitraum (Art. 13)

- **Abs. 8:** Der Support-Zeitraum bemisst sich an der erwarteten Nutzungsdauer und
  beträgt **mindestens fünf Jahre**; kürzer nur, wenn die erwartete Nutzungsdauer
  kürzer ist.
- **Abs. 9:** Sicherheitsupdates müssen nach ihrer Bereitstellung **mindestens
  10 Jahre** verfügbar bleiben, oder für den Rest des Support-Zeitraums, je nachdem,
  was länger ist.
- **Abs. 13:** Technische Dokumentation **10 Jahre** aufbewahren, oder für den
  Support-Zeitraum, je nachdem, was länger ist.

### 3.5 Geltungsbereich

Der CRA gilt für Produkte mit digitalen Elementen, die auf dem EU-Markt
bereitgestellt werden. Open-Source-Entwicklung außerhalb einer kommerziellen
Tätigkeit fällt weitgehend nicht darunter; „Open-Source-Software-Verwalter"
(Art. 24) haben abgeschwächte Pflichten. Das README muss das sagen, damit sich
niemand adressiert fühlt, der es nicht ist.

---

## 4. Getroffene Designentscheidungen

| Thema | Entscheidung |
|---|---|
| npm-Paket / Binary | `cradle-cli` / `cradle` (`cradle` ist auf npm belegt) |
| Monorepo | Root-`package.json` wird `metadata.component`; Workspaces erscheinen als direkte Komponenten. Ein Report pro Repo. `--workspace` später. |
| Lizenzquelle | `node_modules` von der Platte lesen; fehlt es, wird die Lizenz ehrlich als unbekannt gemeldet und im Readiness-Check als offener Punkt geführt. Kein automatischer Netzzugriff. |
| CycloneDX-Version | **1.6** als Default (maximale Kompatibilität), `--spec-version 1.7` als Flag |
| Serialisierung | Selbst gebaut. Das offizielle JSON-Schema liegt unter `schema/` und jeder SBOM-Test validiert dagegen. |
| Baseline vs. VEX | Streng getrennt (siehe 6.4) |
| Lint/Format | Biome (ein Binary für beides, kein Prettier daneben) |
| Build | tsdown |
| Tests | Vitest, Fixtures als echte Verzeichnisse unter `test/fixtures/` |
| CLI-Parsing | `node:util` `parseArgs`, Hilfetexte handgeschrieben |
| Node-Version | `>=22.9.0`. Node 20 ist seit April 2026 EOL — ein Sicherheitswerkzeug sollte kein abgekündigtes Runtime unterstützen. |

### 4.1 Runtime-Dependencies

Jede neue Abhängigkeit wird vorher begründet.

| Paket | Begründung |
|---|---|
| `@npmcli/arborist` | Der einzige Weg zum echten aufgelösten npm-Baum. Auf `^9.9.1` gepinnt: v10 verlangt `^22.22.2 || ^24.15.0 || >=26` und schließt damit auch verbreitete 24.x-Stände aus. Wechsel auf v10, wenn sich das Feld bewegt hat. |
| `packageurl-js` | purl-Encoding ist subtil (Scopes, Qualifier); offizielle Implementierung |
| `yaml` | pnpm-Lockfile und Yarn Berry |
| `spdx-expression-parse` | Lizenzausdrücke validieren statt Strings durchreichen |

Bewusst **nicht** als Dependency, sondern selbst geschrieben:

- **Yarn-Classic-Parser** — `@yarnpkg/lockfile` ist seit 2018 unmaintained.
  ~150 Zeilen eigener Code sind besser als eine tote Abhängigkeit.
- **Argument-Parsing** — `node:util` `parseArgs` reicht.
- **HTTP-Client** — globales `fetch`.
- **Template-Engine** — String-Templates plus ein strikter HTML-Escaper.

---

## 5. Technische Korrekturen zur ursprünglichen Spec

Fünf Punkte, an denen die Umsetzung bewusst von der Vorgabe abweicht:

**a) `hashes` brauchen eine Konvertierung.** npm schreibt `sha512-<base64>`.
CycloneDX verlangt in `hashes[].content` **Hex**. Die Integrity direkt zu übernehmen
erzeugt ein Feld, das Validatoren durchwinken und Konsumenten falsch lesen.
Zusätzlich hasht die Integrity das Tarball, nicht die Komponente — der Hash gehört
darum auch an eine `externalReferences`-Eintragung vom Typ `distribution`.

**b) `metadata.tools` als Array ist seit CycloneDX 1.5 deprecated.** Richtig ist
`metadata.tools.components[]` mit `type: application`.

**c) `bom-ref` kann nicht immer die purl sein.** Dasselbe `name@version` kann im Baum
mehrfach vorkommen (verschachtelte `node_modules` bei Versionskonflikten). Ist
`bom-ref` nicht eindeutig, ist der `dependencies`-Block kaputt — und der ist der
Unterschied zwischen einem echten SBOM und einer Textdatei. Regel: purl als
`bom-ref`, solange eindeutig; bei Kollision ein deterministisches Pfad-Suffix.

**d) `suppress` braucht einen Komponenten-Scope.** Ein OpenVEX-Statement ist immer
(Vulnerability × Produkt/Subkomponente). Nur über die CVE-ID zu unterdrücken würde
die Schwachstelle für *alle* betroffenen Pakete stumm schalten — genau das stille
Ignorieren, das VEX verhindern soll. `--component <purl>` ist Pflicht, sobald mehr
als ein Paket betroffen ist.

**e) Der Cache-Pfad muss einen Fallback haben.** `node_modules/.cache/cradle/`
existiert nicht ohne Install und ist im Monorepo mehrdeutig. Regel:
`node_modules/.cache/cradle` wenn vorhanden, sonst OS-Cache-Verzeichnis,
überschreibbar via `CRADLE_CACHE_DIR`.

---

## 6. Funktionsumfang MVP

### 6.1 `cradle scan`

Ohne Argumente im Projektverzeichnis:

**Dependency-Graph auflösen.** Paketmanager anhand der Lockfile erkennen
(`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`). Für npm
`@npmcli/arborist`. Für pnpm und Yarn die Lockfile direkt parsen — das sind **drei**
Parser, nicht zwei: pnpm v9 (`packages` + `snapshots` getrennt), Yarn Classic
(eigenes Textformat) und Yarn Berry (YAML mit `__metadata`). Bun ist im MVP ein
klarer „nicht unterstützt"-Fehler mit Handlungsanweisung.

Direkte und transitive Abhängigkeiten werden unterschieden, ebenso Production und
Development. **Der Default-Scan umfasst nur Production-Dependencies**, weil das der
CRA-relevante Auslieferungsumfang ist. `--include-dev` erweitert das.

**SBOM erzeugen** in CycloneDX 1.6 (JSON). Pflichtfelder pro Komponente: `bom-ref`,
`type: library`, `name`, `version`, `purl` (korrekt URL-enkodiert, besonders bei
Scoped Packages: `pkg:npm/%40scope/name@1.2.3`), `licenses`, `hashes` (hex, siehe
5a). Die Abhängigkeitsbeziehungen kommen in den `dependencies`-Block, nicht nur eine
flache Liste. Metadaten: eigenes Projekt als `metadata.component`, Zeitstempel,
`metadata.tools.components[]` mit uns selbst.

**Schwachstellen abfragen** über die OSV.dev-Batch-API
(`POST https://api.osv.dev/v1/querybatch`), gefolgt von Einzelabfragen für Details.
Blöcke von maximal 1000 Paketen, Retry mit Backoff bei 429, lokaler Cache.
`--offline` überspringt diesen Schritt und markiert den Report entsprechend.

Severity-Normalisierung: CVSS-Vektor aus `severity[]` bevorzugt, GHSA-Einstufung aus
`database_specific` als Fallback. Der Report weist darauf hin, dass ein
CVSS-Basiswert keine Aussage über Ausnutzbarkeit im konkreten Kontext ist.

**Ergebnis** nach `.cradle/`:

- `sbom.cdx.json` — das SBOM
- `findings.json` — aufgelöste Schwachstellen mit Severity, betroffener Version,
  Fix-Version und Pfad im Dependency-Baum (kürzester Pfad zuerst)
- `report.html` — der Report

**Konsolenausgabe:** kompakte Zusammenfassung — Komponentenzahl, Findings nach
Severity, unterdrückte Findings, die drei wichtigsten Handlungsempfehlungen. Keine
Wall of Text.

### 6.2 Der HTML-Report

Das Herzstück. Eine einzelne, selbstständige HTML-Datei ohne externe Ressourcen, die
man per E-Mail verschicken kann. Kein React, kein Build-Schritt — generiertes HTML
mit eingebettetem CSS und minimalem Vanilla-JS für Filter und Sortierung. Das
eingebettete JSON liegt als `<script type="application/json">` im Dokument, damit der
Report maschinell weiterverarbeitbar bleibt.

Aufbau:

- **Kopf:** Projektname, Version, Scan-Zeitpunkt, Paketmanager, Scope (prod/all),
  Toolversion. Ein Auditor muss auf einen Blick wissen, was wann gescannt wurde.
- **Zusammenfassung:** Komponentenzahl, Findings nach Severity, unterdrückte
  Findings, Lizenzverteilung.
- **CRA-Readiness-Checkliste** (6.5).
- **Findings-Tabelle:** sortierbar nach Severity, filterbar. Pro Eintrag: CVE/GHSA-ID,
  Paket, betroffene Version, Fix-Version, Pfad im Baum (`app > express >
  body-parser`), Link zur OSV-Quelle, bei Unterdrückung die VEX-Begründung.
- **Komponententabelle:** Name, Version, Lizenz, direkt oder transitiv.
- **Fußzeile:** technische Momentaufnahme, keine Rechtsberatung.

Design: ruhig, druckbar, hoher Kontrast. Bedeutung nie allein über Farbe. Kein
Dark-Mode im MVP.

### 6.3 VEX-Unterdrückung

Der praktische Alltagsschmerz ist nicht „ich finde keine Schwachstellen", sondern
„ich ertrinke in Findings, die mich nicht betreffen".

```
cradle suppress <finding-id> --component <purl> --justification <grund> --note "..."
```

schreibt ein Statement in `.cradle/vex.json` im OpenVEX-Format. Erlaubte
Begründungen sind ausschließlich die im Standard definierten:

- `component_not_present`
- `vulnerable_code_not_present`
- `vulnerable_code_not_in_execute_path`
- `vulnerable_code_cannot_be_controlled_by_adversary`
- `inline_mitigations_already_exist`

Freitext über `--note` ist zusätzlich möglich, die Kategorie ist Pflicht. Das ist
bewusst etwas unbequem — genau diese Kategorien machen eine Unterdrückung
auditierbar statt zu einem stillen Ignorieren.

`--expires <datum>` lässt Unterdrückungen ablaufen; sie erscheinen im Report als
„läuft in 12 Tagen ab". Abgelaufene Unterdrückungen greifen nicht mehr.

`.cradle/vex.json` gehört ins Git-Repo des Nutzers und ist der eigentliche Wert, der
über die Zeit entsteht.

### 6.4 `cradle check` — das CI-Gate

Verhält sich wie `scan`, aber mit Exit-Code-Logik und Baseline-Vergleich.
`.cradle/baseline.json` speichert den Stand der akzeptierten Findings; `check`
vergleicht dagegen und meldet nur neue. Das ist der Unterschied zwischen einem Tool,
das man nach zwei Wochen abschaltet, und einem, das bleibt: ein bestehendes Projekt
hat immer Altlasten, und ein Gate, das ab Tag eins rot ist, wird ignoriert.

**Trennung Baseline / VEX — verbindlich:**

- **VEX** heißt „betrifft uns nicht". Dauerhaft, begründet, auditierbar.
- **Baseline** heißt „wissen wir, noch nicht gefixt". Technische Schuld, zeitlich.
- Im Report zwei getrennte Blöcke, nie vermischt.
- **Der Readiness-Check zählt baselined-ohne-VEX weiterhin als offen.** `check`
  bleibt grün, die Checkliste nicht. Sonst wäscht die Baseline Findings still weiß,
  und der Check meldet grün, wo Meldepflicht drohen könnte.

Optionen: `--fail-on <severity>` (Default `high`), `--baseline` schreibt den
aktuellen Stand als neue Baseline, `--no-baseline` prüft gegen alles.

Exit-Codes: `0` sauber, `1` neue Findings über der Schwelle, `2` Toolfehler. Die
Unterscheidung zwischen 1 und 2 ist wichtig, damit CI-Fehler nicht als
Sicherheitsproblem durchgehen.

Ausgabe im CI-Modus als kompakte Liste, optional `--format github` für
GitHub-Actions-Annotationen (`::error file=...`).

### 6.5 CRA-Readiness-Checkliste

Der Grund, warum jemand uns statt eines generischen SBOM-Generators nimmt. Geprüft
wird nicht nur der Paketbestand, sondern auch die Dokumentationspflichten drumherum:

1. Existiert ein SBOM und ist es aktueller als die Lockfile?
2. Existiert eine `SECURITY.md` mit Kontaktadresse für Schwachstellenmeldungen?
   (Der CRA verlangt eine Coordinated-Vulnerability-Disclosure-Policy.)
3. Ist ein Support-Zeitraum dokumentiert? (Art. 13 Abs. 8, siehe 3.4.)
4. Sind Update-Verfügbarkeit und Doku-Aufbewahrung bedacht? (Art. 13 Abs. 9 und 13.)
5. Sind alle Komponenten mit einer Lizenz versehen? Gibt es Pakete ohne oder mit
   unklarer Lizenz?
6. Gibt es Abhängigkeiten ohne Release seit über 24 Monaten oder als deprecated
   markiert?
7. Gibt es offene Findings ohne Fix und ohne VEX-Statement? (Die könnten im Ernstfall
   meldepflichtig werden.)

Jeder Punkt bekommt einen Status — **erfüllt / teilweise / offen / nicht prüfbar** —
und einen konkreten nächsten Schritt, formuliert als Handlungsanweisung, nicht als
Vorwurf.

Punkte, die Netzzugriff brauchen (6: Release-Alter, deprecated), melden unter
`--offline` ehrlich **„nicht prüfbar"** statt „erfüllt".

Konfigurierbar über `.cradle/config.json`: `supportPeriodEnd`, `productName`,
`contactEmail`.

### 6.6 GitHub Action

Composite Action unter `action.yml` im selben Repo, ruft `npx cradle-cli@<version>`
auf:

```yaml
- uses: DEIN-USER/cradle@v1
  with:
    fail-on: high
    upload-artifact: true
    comment-on-pr: true
```

Lädt den Report als Artifact hoch und schreibt bei neuen Findings einen
PR-Kommentar — idempotent über einen Marker im Kommentar-Body, also bestehenden
aktualisieren statt neuen anlegen. Braucht `permissions: pull-requests: write`; das
muss im README stehen, sonst scheitert jeder beim ersten Versuch.

---

## 7. Ausdrücklich nicht im MVP

Gehört so ins README, damit klar ist: Absicht, keine Lücke.

- Andere Ökosysteme als npm (kein Python, kein Go, keine Container)
- SPDX als Ausgabeformat (kommt später, CycloneDX reicht für den Anfang)
- Signierte Attestationen, Sigstore, SLSA
- Eine Weboberfläche oder ein gehosteter Dienst
- Automatische Pull Requests für Updates (das macht Dependabot besser)
- Lizenz-Policy-Enforcement (nur anzeigen, nicht blockieren)

---

## 8. Architektur

Kernlogik strikt getrennt von CLI und Darstellung, damit das Paket auch als Library
nutzbar ist.

```
src/
  cli/            Befehle, Argument-Parsing, Konsolenausgabe
  core/
    resolve/      Paketmanager-Erkennung, Lockfile-Parser, Dependency-Graph
    sbom/         CycloneDX-Erzeugung, PURL-Bau, Lizenz-Normalisierung
    vulns/        OSV-Client, Caching, Severity-Normalisierung
    vex/          OpenVEX lesen/schreiben, Ablaufprüfung, Anwendung auf Findings
    readiness/    Die CRA-Checkliste
    baseline/     Diffing gegen die Baseline
  report/         HTML-Generierung, Templates, CSS
  types/          Gemeinsame Typen, alle aus einer Datei re-exportiert
```

**Regel:** Funktionen in `core/` bekommen ihre Eingaben übergeben und schreiben
nichts direkt auf die Platte oder die Konsole. Dateizugriff und Ausgabe passieren in
`cli/`. Das macht die Tests einfach.

## 9. Qualitätsanspruch

- Jeder Lockfile-Parser bekommt mindestens ein echtes Fixture-Projekt als Test,
  inklusive Scoped Packages, Peer-Dependencies, Workspaces und einem Paket ohne
  Lizenzangabe.
- Fixtures enthalten nur `package.json` und Lockfile, kein installiertes
  `node_modules`. Wo ein Parser Daten von der Platte braucht (pnpm, Yarn), wird
  ein minimaler `node_modules`-Baum aus reinen `package.json`-Dateien eingecheckt.
  Tests laufen damit offline und deterministisch, ohne `npm install`.
- Der OSV-Client wird in Tests gemockt, nie live abgefragt.
- Fehlermeldungen sagen, was schiefging und was der Nutzer tun soll. „ENOENT" ist
  keine Fehlermeldung.
- Keine `any`-Typen ohne Kommentar, der erklärt warum.
- Conventional Commits, kleine Commits, jeder Commit lauffähig.

## 10. Reihenfolge der Umsetzung

Nach jedem Meilenstein wird angehalten.

0. **Gerüst** — Repo, Configs, Lizenz, CI, `SPEC.md`, Fixture-Verzeichnisse.
1. **Typen, npm-Parser, CycloneDX** — Ergebnis: `cradle scan --offline` schreibt ein
   gegen das offizielle 1.6-Schema validiertes `sbom.cdx.json`.
2. **OSV-Client** mit Cache, Findings-Auflösung inklusive Pfad im Baum.
3. **HTML-Report.** Erst ein statischer Entwurf mit echten Daten zur Abnahme, dann
   Generierungscode. Hier wird bewusst Zeit investiert — das ist das Produkt.
4. **VEX-Unterdrückung** und `suppress`-Befehl.
5. **Baseline und `check`** mit Exit-Codes.
6. **CRA-Readiness-Checkliste.**
7. **pnpm-, Yarn-Classic- und Yarn-Berry-Parser.**
8. **GitHub Action.**
9. **README, Beispielprojekt, Release-Vorbereitung.**

---

## 11. Quellen

- [Verordnung (EU) 2024/2847, EUR-Lex](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng)
- [CRA-Zusammenfassung der EU-Kommission](https://digital-strategy.ec.europa.eu/en/policies/cra-summary)
- [CycloneDX-Spezifikation](https://github.com/CycloneDX/specification)
- [OpenVEX-Spezifikation](https://github.com/openvex/spec)
- [OSV.dev API](https://google.github.io/osv.dev/api/)

## 12. Rechtlicher Hinweis

`cradle` ist ein technisches Hilfsmittel zur Dokumentation und Prozessunterstützung.
Es ist keine Rechtsberatung, keine Konformitätsbewertung und keine
Konformitätserklärung. Ob ein Produkt die Anforderungen der Verordnung (EU) 2024/2847
erfüllt, entscheidet nicht dieses Werkzeug. Die harmonisierten Normen zum CRA sind
zum Stand dieses Dokuments nicht final.
