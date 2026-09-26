# cradle — Spezifikation

> **German-language working spec; README is authoritative for users.**
> This document records what was decided and why, in German, for whoever
> develops cradle. Anything a user needs is in the English
> [`README.md`](README.md); where the two appear to differ about a user-visible
> promise, the README is the one that was published.

Verbindliche Referenz für die Entwicklung. Enthält die ursprüngliche Spezifikation
des Maintainers, die daran vorgenommenen fachlichen Korrekturen und die getroffenen
Designentscheidungen. Bei Widerspruch gilt dieses Dokument.

- **npm-Paket:** `cradle-cli`
- **Binary:** `cradle`
- **Repo:** `github.com/P-hinn/cradle-cli`
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
| `packageurl-js` | purl-Encoding ist subtil (Scopes, Qualifier); offizielle Implementierung |
| `yaml` | pnpm-Lockfile und Yarn Berry |
| `spdx-expression-parse` | Lizenzausdrücke validieren statt Strings durchreichen |
| `semver` | Korrekte Versionsordnung inkl. Prereleases für die Fix-Auswahl |

**`@npmcli/arborist` wurde vor dem Release wieder entfernt.** Es lieferte den
richtigen Baum, brachte aber **115 eigene transitive Abhängigkeiten** mit — bei
einem Werkzeug, dessen Thema Größe und Herkunft von Abhängigkeitsbäumen ist, war
das nicht zu rechtfertigen. Die `packages`-Map von `package-lock.json` ab
lockfileVersion 2 *ist* der materialisierte Baum: Pfade, aufgelöste Versionen,
Integrity und seit v2 auch Lizenzen. Kanten folgen Nodes eigener
Auflösungsregel — vom Ort des Abhängigen die `node_modules`-Kette hochlaufen.
Genau das lässt ein doppelt installiertes Paket auf die richtige Kopie zeigen.

Belegt ist die Gleichwertigkeit durch Snapshots von Arborists eigener Ausgabe,
aufgenommen bevor es entfernt wurde (`test/fixtures/expected/`), plus einen
Vergleich auf dem echten 248-Paket-Baum dieses Repos. Bilanz:

| | mit arborist | ohne |
|---|---|---|
| Produktions-Komponenten | 118 | **6** |
| `node_modules` (prod) | 22 MB | **1,7 MB** |
| Pakete auf der Platte | 88 | **6** |

Nicht gebündelt wird bewusst: die vier verbliebenen Abhängigkeiten bleiben extern
und damit unabhängig von einem cradle-Release aktualisierbar. Das ist für ein
Supply-Chain-Werkzeug wichtiger als eine Null-Dependency-Zahl.

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
Parser, nicht zwei: pnpm v9/v10 (`packages` + `snapshots` getrennt), Yarn Classic
(eigenes Textformat) und Yarn Berry (YAML mit `__metadata`). Bun ist ein klarer
„nicht unterstützt"-Fehler mit Handlungsanweisung.

Alle vier Parser münden in dieselbe Zwischendarstellung (`core/resolve/graph.ts`),
damit prod/dev-Trennung, `bom-ref`-Vergabe und Komponentenbau einmal geschrieben
sind und sich überall gleich verhalten. Der Test, der zählt, ist die Äquivalenz:
vier Fixtures mit identischen Abhängigkeiten müssen identische Komponenten und
identische Kanten liefern.

Was pro Format zu beachten war:

| | prod/dev in der Lockfile? | Integrity? | Lizenzen? |
|---|---|---|---|
| npm | ja | ja (SRI) | ja, ab lockfileVersion 2 |
| pnpm | ja, pro Importer | ja (SRI) | **nein** |
| Yarn Classic | **nein** | ja (SRI) | **nein** |
| Yarn Berry | **nein** | **nein** (siehe unten) | **nein** |

* **prod/dev wird für Yarn abgeleitet.** Classic kennt gar keine Markierung, Berry
  faltet die dev-Abhängigkeiten des Roots mit den übrigen zusammen. Also wird für
  alle Ökosysteme gleich gerechnet: einmal von den Produktions-Abhängigkeiten aus
  laufen, einmal von den Entwicklungs-Abhängigkeiten, und „dev" ist, was der erste
  Lauf nicht erreicht hat.
* **Yarn Berrys `checksum` ist kein Tarball-Hash.** Er ist sha512-groß und sieht
  aus wie ein Integrity-Wert, ist aber Yarns eigener Cache-Schlüssel über Yarns
  eigenes Archivformat: für dasselbe Paket notiert npm `4162e5d8…` und Yarn
  `6d43a916…`. Ihn als CycloneDX-SHA-512 auszugeben wäre eine plausibel
  aussehende Lüge — Berry-SBOMs tragen deshalb **keine** Hashes.
* **pnpm-Snapshot-Schlüssel tragen den Peer-Kontext** (`debug@4.3.7(supports-color@7.2.0)`).
  Der muss abgeschnitten werden, sonst ist dasselbe Paket unter zwei Peer-Sets
  zwei Komponenten.
* **pnpm-Lockfiles vor v9 werden abgelehnt.** Vor v9 gab es die
  `packages`/`snapshots`-Trennung nicht; der alte Aufbau würde in einen leeren
  Baum parsen und wie ein Projekt ohne Abhängigkeiten aussehen.
* **Lizenzen kommen bei pnpm und Yarn von der Platte** (`node_modules`), wie in §4
  entschieden. Fehlt sie — frischer Klon, oder Yarn PnP — steht „unbekannt", und
  der Readiness-Check führt es als offenen Punkt. Kein stiller Netzzugriff, keine
  erfundene Antwort.

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

Severity-Normalisierung: Der CVSS-v3-Basiswert wird aus dem Vektor **selbst
berechnet** (die Formel ist von FIRST vollständig spezifiziert, also exakt statt
geschätzt) und in die Stufen critical/high/medium/low überführt. Für CVSS v2 und
v4 wird nicht gerechnet — v4 braucht eine große Nachschlagetabelle, und Raten wäre
schlechter als das Label der Datenbank. Dann greift `database_specific.severity`
(GitHub sagt `MODERATE`, wo CVSS `MEDIUM` sagt). Jedes Finding trägt in
`severitySource`, welcher Weg es war. Der Report weist darauf hin, dass ein
CVSS-Basiswert die Schwachstelle abstrakt beschreibt und nichts über
Erreichbarkeit im konkreten Projekt aussagt.

Zurückgezogene Advisories (`withdrawn`) werden verworfen.

Der Cache liegt unter dem Schlüssel `osv/v1/<id>@<modified>`. Weil der
`modified`-Zeitstempel des Advisories Teil des Schlüssels ist, invalidiert sich
ein geändertes Advisory von selbst; ein Wiederholungslauf kostet genau eine
Batch-Anfrage. `--no-cache` schaltet ihn ab.

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

Umgesetzte Details:

* **Severity doppelt kodiert.** Jede Stufe steht ausgeschrieben da *und* trägt ein
  ordinales Glyph (`●●●` critical bis `○○○` low). Damit überlebt der Rang
  Graustufendruck und Farbfehlsichtigkeit.
* **Severity-Herkunft steht im Detail.** Entweder „CVSS v3.1 base score 9.8
  <Vektor>" oder „wie von der Advisory-Datenbank bewertet" — plus der Satz, dass
  ein Basiswert die Schwachstelle abstrakt beschreibt und nichts über
  Erreichbarkeit im Projekt aussagt.
* **Escaping an genau einer Stelle** (`report/escape.ts`). Paketnamen,
  Advisory-Texte und Referenz-URLs kommen aus dem Netz, und der Report wird lokal
  geöffnet — ein eingeschleustes Skript liefe mit `file://`-Origin. URLs werden
  auf `http`/`https` beschränkt; im eingebetteten JSON bleiben sie unverändert
  erhalten, weil dieser Block ein wortgetreues Protokoll ist und dort inert.
* **Ohne JavaScript vollständig lesbar.** Filter- und Sortierleisten sind
  `hidden`, bis das Skript sie aktiviert; die Tabellen stehen komplett im HTML.
* **Im Druck kommt alles zurück.** `@media print` blendet die Bedienelemente aus,
  hebt jede vom Filter versteckte Zeile wieder ein und schreibt Link-Ziele aus —
  ein gedruckter Report muss vollständig sein.
* **Report und SBOM tragen dieselbe `serialNumber`,** damit ein Prüfer sie
  einander zuordnen kann.
* **Ein leerer Befund wird als Momentaufnahme benannt,** nicht als Freibrief; ein
  Offline-Lauf zeigt gar keine Findings-Tabelle, weil eine leere Tabelle wie ein
  geprüftes „nichts gefunden" aussähe.

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
„läuft in 12 Tagen ab", und die Konsole warnt 30 Tage vorher. Abgelaufene
Unterdrückungen greifen nicht mehr — genau das ist der Zweck: eine Entscheidung
über eine Abhängigkeit soll erneuert werden müssen, statt still ihre Begründung
zu überleben. Das abgelaufene Statement bleibt am Finding hängen, damit der
Report „ist ausgelaufen" sagen kann und das Finding nicht ohne Vorgeschichte
wieder auftaucht.

**Abweichung vom Standard:** OpenVEX kennt kein Ablaufdatum. Deshalb steht es als
`cradle:expires` am Statement — mit Präfix, damit es erkennbar keine
OpenVEX-Eigenschaft ist und konforme Konsumenten es ignorieren. Alles andere in
`vex.json` ist reines OpenVEX v0.2.0.

Weitere umgesetzte Details:

* **Autor ist Pflicht.** OpenVEX verlangt ihn, und eine unsignierte
  Unterdrückung ist im Audit wenig wert. Default ist `git config user.email`;
  fehlt beides, bricht der Befehl mit einer Handlungsanweisung ab.
* **Identifikation über GHSA *oder* CVE.** Leute notieren sich die CVE, über die
  sie gelesen haben; OSV schlüsselt npm-Advisories nach GHSA. Beides wird
  akzeptiert, geschrieben wird die von cradle geführte ID plus `aliases`.
* **`--component` ist Pflicht, sobald mehrere Komponenten betroffen sind.** Nur
  über die Advisory-ID zu unterdrücken würde die Schwachstelle überall stumm
  schalten — genau die pauschale Abtuung, die VEX verhindern soll.
* **Wiederholtes `suppress` ersetzt das Statement,** statt ein zweites
  anzuhängen. Eine Korrektur soll als Korrektur lesbar sein, nicht als zwei
  widersprüchliche Aussagen.
* **Eine kaputte `vex.json` bricht den Scan ab.** Sie stillschweigend zu
  überspringen hieße, Findings erneut zu melden, über die das Team längst
  entschieden hat.
* **Unterdrückte Findings bleiben im Report und in `findings.json`,** getrennt
  ausgewiesen. Ein Prüfer muss der Entscheidung widersprechen können.
* **Statements, die auf nichts passen,** werden gemeldet — meist wurde das
  Finding durch ein Update behoben und das Statement ist Altlast.

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

**Identität eines Findings in der Baseline: Advisory-ID + Paketname, ohne
Version.** Mit Version würde jeder Patch-Bump eines weiterhin verwundbaren Pakets
wie ein brandneues Finding aussehen — und ein Gate, das bei fremdem Rauschen rot
wird, wird abgeschaltet. Die Severity beim Akzeptieren wird mitgeschrieben:
Wurde ein Advisory seither **schlechter** eingestuft, gilt es wieder als neu. Ein
akzeptiertes Medium ist kein akzeptiertes Critical.

Weitere umgesetzte Details:

* `--fail-on never` meldet alles und lässt nichts scheitern — für Teams, die das
  Gate schrittweise einführen.
* Baseline-Einträge, die im Scan nicht mehr vorkommen, werden als „erledigt"
  ausgewiesen, damit die Datei aufgeräumt werden kann.
* Eine kaputte `baseline.json` bricht ab, statt still als „keine Baseline"
  durchzugehen — das würde das Gate unbemerkt scharf schalten.
* `--format github` schreibt Annotationen mit **Datei und Zeilennummer** aus der
  `package.json`, wenn es eine direkte Abhängigkeit ist. Eine Annotation an der
  Zeile, die man ändern kann, wird gelesen; eine auf Zeile 1 nicht. Transitive
  Pakete stehen nirgends in der `package.json` und bekommen stattdessen den Pfad
  im Baum in die Meldung.
* `scan` und `check` teilen sich dieselbe Pipeline (`cli/pipeline.ts`). Sie müssen
  sich darüber einig sein, was ein Finding ist — sonst hieße ein grünes Gate etwas
  anderes als ein sauberer Report.

**Wart in der CLI-Benennung:** `--baseline` und `--no-baseline` sind keine
Gegenteile. Ersteres *schreibt* die Baseline, letzteres *ignoriert* sie. So steht
es in der ursprünglichen Spezifikation und so ist es umgesetzt; beide sind als
eigenständige Optionen deklariert, nicht als Negation.

Ausgabe im CI-Modus als kompakte Liste, optional `--format github` für
GitHub-Actions-Annotationen (`::error file=...`).

### 6.5 CRA-Readiness-Checkliste

Der Grund, warum jemand uns statt eines generischen SBOM-Generators nimmt. Geprüft
wird nicht nur der Paketbestand, sondern auch die Dokumentationspflichten drumherum.
**Sechs** Punkte (die ursprünglich getrennten Punkte zu Art. 13 Abs. 8, 9 und 13
sind zusammengefasst — die beiden Zehnjahresfristen lassen sich aus einem Repo
nicht prüfen, gehören aber in die Handlungsanweisung):

| ID | Prüfung | Bezug |
|---|---|---|
| `sbom` | Existiert ein SBOM und ist es aktueller als die Lockfile? | Anhang I Teil II Nr. 1 |
| `disclosure` | Existiert eine `SECURITY.md` **mit erreichbarem Kontakt** (Adresse oder Meldelink)? | Anhang I Teil II Nr. 5 |
| `support-period` | Ist der Support-Zeitraum dokumentiert und erreicht er die Fünfjahresgrenze? | Art. 13 Abs. 8, 9, 13 |
| `licences` | Sind alle Komponenten mit einer Lizenz versehen? | Anhang I Teil II Nr. 1 |
| `maintenance` | Deprecated oder seit über 24 Monaten ohne Release? | Anhang I Teil II Nr. 2 |
| `unresolved` | Offene Findings ohne Fix und ohne VEX-Statement? | Art. 14 |

Jeder Punkt bekommt einen Status — **erfüllt / teilweise / offen / nicht prüfbar** —
und einen konkreten nächsten Schritt, formuliert als Handlungsanweisung, nicht als
Vorwurf. Wo cradle es nicht wissen kann, steht **nicht prüfbar**: eine Checkliste,
die grün meldet, weil sie nicht hingesehen hat, ist schlechter als keine.

Konfigurierbar über `.cradle/config.json`: `productName`, `contactEmail`,
`supportPeriodEnd`, `placedOnMarket`. Ein **unbekannter Schlüssel bricht ab** —
ein vertipptes `supportPeriodEndd` würde sonst still „nicht dokumentiert" melden,
während der Nutzer sicher ist, es dokumentiert zu haben.

Umgesetzte Details:

* **Die Fünfjahresgrenze wird kalendergenau gerechnet.** Fünf Jahre sind je nach
  Schaltjahr 1825 oder 1826 Tage; durch eine mittlere Jahreslänge geteilt ergeben
  exakt fünf Kalenderjahre 4,999 — und das Werkzeug würde einem konformen Nutzer
  sagen, er sei es nicht. Verglichen wird deshalb Datum gegen Datum. Fehlt
  `placedOnMarket`, ist der Punkt „teilweise": die Grenze ist ohne Startdatum
  nicht prüfbar.
* **`maintenance` fragt die npm-Registry** und ist unter `--offline` „nicht
  prüfbar". Zwei Signale mit sehr unterschiedlichen Kosten, deshalb zwei Umfänge:
  *Deprecated* kommt aus dem Einzelversions-Manifest (wenige KB) und wird für
  **alle** Komponenten geprüft; *letztes Release* steht nur im vollständigen
  Packument (hunderte KB) und wird nur für **direkte** Abhängigkeiten geholt. Der
  Report sagt beides ausdrücklich. Der `modified`-Zeitstempel der Registry sieht
  wie eine billige Abkürzung aus und ist keine — er bewegt sich bei
  Metadatenänderungen: `request` gilt dort als „diesen Monat geändert", das letzte
  echte Release war 2020.
* **Registry-Ausfälle brechen nichts ab.** Diese Information verbessert die
  Checkliste, sie ist nicht der Zweck des Werkzeugs; ohne Antwort steht „nicht
  prüfbar".
* **`unresolved` zählt baselined-ohne-VEX als offen.** `cradle check` bleibt darauf
  grün, weil ein Gate, das ab Tag eins rot ist, abgeschaltet wird — aber die
  Baseline sagt „wissen wir", nicht „betrifft uns nicht", und nur VEX sagt
  Letzteres. Würde die Checkliste die Baseline mitzählen, würde die Baseline
  Findings still weißwaschen, und zwar genau dort, wo es am meisten zählt.

### 6.6 GitHub Action

Composite Action unter `action.yml` im selben Repo (`P-hinn/cradle-cli`), ruft
`npx cradle-cli@<version>` auf:

```yaml
permissions:
  contents: read
  pull-requests: write   # nur für comment-on-pr

steps:
  - uses: actions/checkout@v5
  - uses: actions/setup-node@v5
    with: { node-version: '22' }
  - uses: P-hinn/cradle-cli@v0.1.3
    with:
      fail-on: high
      upload-artifact: true
      comment-on-pr: true
```

Ablauf: `scan` (schreibt SBOM, Findings, Report, Readiness) → `check`
(Annotationen + Exit-Code) → Artifact-Upload → PR-Kommentar → Fehlschlag bei
neuen Findings.

Umgesetzte Details:

* **Der PR-Kommentar wird vom Werkzeug erzeugt, nicht von der Action.**
  `cradle check --format markdown` gibt den fertigen Body aus; die Action pipet
  ihn nur weiter. Damit ist die Formatierung getestet, und das CLI braucht
  **keinerlei Schreibzugriff auf GitHub** — das Posten macht `gh api` in der
  Action.
* **Idempotent über einen Marker** (`<!-- cradle-cli:report -->`): existiert ein
  Kommentar mit diesem Marker, wird er per `PATCH` aktualisiert, sonst per `POST`
  angelegt. Ein PR, der pro Push einen Kommentar sammelt, ist ein PR, in dem
  niemand mehr Kommentare liest. Ein Test hält Marker im Werkzeug und Marker in
  der Action aneinander gekoppelt.
* **Exit-Code 2 wird als Build-Fehler behandelt, nicht als Sicherheitsergebnis.**
  Der `check`-Schritt läuft bewusst ohne `set -e` — ein Exit ungleich null *ist*
  das Ergebnis. Damit ein fehlgeschlagener Download nicht als „Exit 1 = neue
  Findings" durchgeht, läuft dasselbe Paket vorher im `scan`-Schritt **mit**
  `set -e`: ein Installationsproblem lässt den Job dort scheitern.
* **Keine `${{ }}`-Interpolation in `run`-Blöcken.** Jeder Wert kommt über
  `env:` — direkt eingesetzte Ausdrücke sind ein Script-Injection-Loch. Ein Test
  prüft das.
* **`--fail-on never`** meldet und lässt nichts scheitern, für die schrittweise
  Einführung.

Die Action lässt sich hier nicht ausführen, deshalb prüft `test/action.test.ts`
die Fehler, die sonst erst in einer fremden Pipeline auffielen: Tippfehler in
Input-Referenzen, `run`-Schritte ohne `shell`, ungepinnte `uses`-Versionen, ein
abgedrifteter Marker. Die Shell-Schritte selbst wurden lokal gegen ein echtes
Projekt ausgeführt.

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
  Lizenzangabe. Bestand unter `test/fixtures/`:

  | Fixture | Deckt ab |
  |---|---|
  | `npm-basic` | Scoped Package, transitive Kette, prod/dev-Trennung |
  | `npm-workspaces` | Workspace-Links, automatisch installierter Peer-Dep, Paket ohne Lizenzfeld, privates Root |
  | `npm-duplicates` | Dasselbe Paket zweimal im Baum, verschachtelt unter einem Dependent |
  | `pnpm-basic`, `yarn-classic-basic`, `yarn-berry-basic` | Dieselben Abhängigkeiten wie `npm-basic`, damit die vier Parser gegeneinander geprüft werden können |
  | `npm-edge-cases` | `npm:`-Alias, `git+`, `file:`, `bundledDependencies`, optionale Dep, `overrides`, private Registry, deklariert-aber-nicht-in-der-Lockfile (§15) |
  | `pnpm-edge-cases` | git (Key trägt URL), `file:` (`type: directory`, keine Version), `link:` außerhalb des Workspace, unaufgelöst |
  | `yarn-berry-edge-cases` | Alias über `resolution`, `patch:`, git, `portal:` mit `linkType: soft`, `::locator=`-Suffix |
  | `yarn-classic-edge-cases` | git und `file:` allein aus dem Descriptor, unaufgelöst |
  | `detect/*` | Lockfile-Erkennung für npm, pnpm, Yarn Classic, Yarn Berry, Bun, sowie fehlende Lockfile und Nicht-Projekt |

  Jedes `*-edge-cases`-Fixture trägt eine `README.md`, die festhält, womit es
  erzeugt wurde und welche Einträge von Hand geschrieben sind. Diese Unterscheidung
  ist nicht Kosmetik: drei der in §15 beschriebenen Fehler waren zuerst durch
  *falsch geratene* Fixtures verdeckt.

  Die pnpm- und Yarn-Fixtures tragen ein eingechecktes `node_modules` aus **nur
  `package.json`-Dateien** — kein Code —, weil ihre Lockfiles keine Lizenzen
  führen. Damit laufen die Tests offline und deterministisch ohne Installation.

- Fixtures enthalten nur `package.json` und Lockfile, kein installiertes
  `node_modules`. Wo ein Parser Daten von der Platte braucht (pnpm, Yarn), wird
  ein minimaler `node_modules`-Baum aus reinen `package.json`-Dateien eingecheckt.
  Tests laufen damit offline und deterministisch, ohne `npm install`.
- Jedes erzeugte SBOM wird im Test gegen die eingecheckten offiziellen
  CycloneDX-Schemata validiert (1.6 und 1.7), nicht gegen handgeschriebene
  Erwartungen.
- Der OSV-Client wird in Tests gemockt, nie live abgefragt. Die Antworten unter
  `test/fixtures/osv/` sind einmal echt aufgezeichnet und werden abgespielt; ein
  Setup-File ersetzt `globalThis.fetch` durch einen Werfer, damit ein vergessener
  Injektionspunkt laut scheitert statt still ins Netz zu gehen.
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

---

# Nachträge nach dem ersten Release

Die Abschnitte 1–12 beschreiben den Stand bis 0.1.3. Alles darunter wurde danach
entschieden und ergänzt sie, statt sie zu ersetzen. Neue Abschnitte werden
angehängt, damit die Nummern in 1–12 als Referenzen stabil bleiben.

## 13. Repo-Infrastruktur

### 13.1 Continuous Integration (`.github/workflows/ci.yml`)

Läuft auf `push` nach `main` und auf jeden `pull_request`. Matrix: Node **22 und
24** × **ubuntu, macos, windows** — sechs Kombinationen, keine Stichprobe davon.

**Warum drei Betriebssysteme.** Die Lockfile-Parser setzen Pfade zusammen, und
`node_modules`-Ketten werden hochgelaufen (§4.1). Ein Trennzeichen-Fehler, der
nur unter Windows auftritt, erreicht sonst einen Nutzer, bevor er uns erreicht.
`fail-fast: false`, weil ein abgebrochener macOS-Lauf genau die Information
verschweigt, die man braucht: ob der Fehler plattformspezifisch war.

**Warum Node 24 mitläuft.** 22.9 ist der deklarierte Boden (`engines`), 24 ist
aktuell. Ein Test prüft, dass die untere Matrix-Stufe und `engines.node`
zusammenpassen; ein angehobener Boden ohne angehobene Matrix wäre sonst
unbemerkt.

**Schritte:** `npm ci`, `lint`, `typecheck`, `test`, `build` — und danach das
gebaute CLI gegen `examples/express-service`:

* `scan --offline` muss die drei Dateien nicht-leer schreiben, und
  `findings.json` muss `offline: true` tragen. Eine leere Findings-Liste ohne
  diese Markierung liest sich wie ein geprüftes „nichts gefunden" (§6.2).
* `check --offline` muss **0** liefern, und `check --offline ./does-not-exist`
  muss **2** liefern. Beide Seiten des Exit-Code-Vertrags (§6.4), nicht nur die
  glückliche.

**`--offline` ist hier keine Bequemlichkeit.** Ein CI-Job, der `api.osv.dev`
abfragt, macht eine fremde Störung zu einem roten Build in diesem Repo und den
Lauf nebenbei nicht reproduzierbar. Ein Test prüft, dass **jeder** Aufruf des
gebauten CLI in `ci.yml` `--offline` trägt.

**Falle, die einen eigenen Test bekommen hat.** GitHub startet `shell: bash` als
`bash --noprofile --norc -eo pipefail`. Das `-e` kommt von außen und wird von
einem `set -uo pipefail` im Skript **nicht** abgeschaltet. Ein Schritt, der `$?`
ausliest, stirbt damit am ersten Exit ungleich null — die Assertion läuft nie und
der Schritt ist grün, weil er nicht hingesehen hat. Deshalb: `set +e` explizit,
und ein Test, der jeden Schritt mit `$?` darauf festnagelt. Dieselbe Falle ist in
§6.6 für die Action beschrieben; hier ist sie zum zweiten Mal aufgetreten.

### 13.2 CodeQL und OpenSSF Scorecard

**CodeQL** mit `javascript-typescript` und dem Paket `security-extended`, nicht
dem Default. Die beiden Fragen, die hier zählen, stehen nur im erweiterten Paket:
Pfad-Traversal aus dem Projektverzeichnis heraus (§SECURITY.md) und unsichere
HTML-Konstruktion im Report-Generator. Läuft zusätzlich wöchentlich — ein Repo
mit vier Abhängigkeiten bekommt trotzdem neue Queries.

**Scorecard** mit `publish_results: true`. Für ein Werkzeug, dessen Thema
Supply-Chain-Nachweise sind, ist ein veröffentlichter, nachprüfbarer Score das
Mindeste; ein Badge, dem man nur glauben kann, wäre genau die Sorte Nachweis, die
cradle anderen nicht abnimmt. `persist-credentials: false` beim Checkout.

**Actions werden auf `@vN` gepinnt, nicht auf einen SHA.** Scorecards
`Pinned-Dependencies`-Check bewertet SHA-Pinning besser. Die Entscheidung geht
trotzdem bewusst anders: `@vN` plus wöchentliches Dependabot für
`github-actions` hält die Versionen aktuell und lesbar, und ein bestehender Test
(`test/action.test.ts`) erzwingt das Pinning-Muster repo-weit. Ein niedrigerer
Punktwert in einem Unterpunkt ist hier der ehrlichere Preis.

### 13.3 Dependabot

npm und `github-actions`, wöchentlich, **gruppiert** — Runtime und Development
getrennt. Vier Runtime-Abhängigkeiten und eine Handvoll Dev-Abhängigkeiten
ergeben einen prüfbaren Pull Request pro Woche; acht einzelne öffnet niemand.
Commit-Präfixe `chore` bzw. `ci`, passend zu §9.

**`examples/express-service` ist ausdrücklich nicht eingetragen.** Das Beispiel
ist auf absichtlich veraltete Abhängigkeiten gepinnt, damit es Findings
produziert. Es zu aktualisieren würde es abschaffen. Ein Test hält fest, dass
kein Dependabot-Eintrag auf ein anderes Verzeichnis als `/` zeigt, damit diese
Auslassung als Entscheidung erkennbar bleibt und nicht als Versehen.

### 13.4 Community-Dateien

`CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1, Kontakt
identisch mit `SECURITY.md` — ein Test koppelt beide, damit nicht zwei Adressen
auseinanderlaufen), `PULL_REQUEST_TEMPLATE.md` und drei Issue-Templates.
`blank_issues_enabled: false`: ein leeres Issue ist der Weg, auf dem eine
Schwachstelle öffentlich wird.

Das dritte Template, **false-positive-finding**, ist das eigentliche. Es verlangt
**Package Manager, Lockfile-Version und Advisory-ID** als Pflichtfelder — ohne
alle drei ist ein False Positive nicht reproduzierbar, und ein nicht
reproduzierbares False Positive ist eine Meinung. Es trennt außerdem vorab drei
Fälle, die sonst jeder einzeln beantwortet werden müssten: ein falsches Advisory
gehört zu OSV, ein zutreffendes Advisory ohne Bezug zum Projekt gehört in
`cradle suppress`, und hierher gehört nur cradles eigene Mechanik — falsch
gematchte Ranges, falsch gerechnetes CVSS, falsche Fix-Version, falscher Pfad.

`CONTRIBUTING.md` beschreibt zwei Sorten Fixture getrennt, weil sie
unterschiedliche Aufgaben haben: `test/fixtures/` für *was cradle mit einer Form
macht* (klein, handgeschrieben, im Diff lesbar) und `test/corpus/` für *hält
cradle eine echte Lockfile in echter Größe aus* (siehe §14).

## 14. Release-Prozess: die Lücke nach 0.1.3

`v0.1.3` hat zwei Fehler nacheinander offengelegt.

**Erstens, die ursprüngliche Ursache.** Release-Assets sind nach Dateinamen
verschlüsselt, und beide SBOMs heißen dort, wo sie geschrieben werden,
`sbom.cdx.json`. Der zweite Upload kam als `HTTP 404` zurück. Das Release war
damit angelegt, der Lauf aber rot, und die Assets fehlten. Behoben durch
eindeutige Namen (`<paket>-<version>-sbom.cdx.json`) und dadurch, dass der
Workflow wiederholbar wurde: `gh release view` → `edit` oder `create`, Upload mit
`--clobber`. Ein fehlgeschlagener Lauf soll durch einen zweiten Lauf zu
reparieren sein, nicht durch eine verbrannte Versionsnummer.

**Zweitens, die Lücke, die dadurch entstand.** Ein Wiederholungslauf überspringt
`npm publish`, wenn die Version schon auf der Registry liegt — baut die Assets
aber neu. Wurde der Tag zwischenzeitlich verschoben, beschreiben SBOM und Report
auf dem Release einen anderen Commit als das veröffentlichte Tarball. Genau das
war nach 0.1.3 der Zustand: npm führt `gitHead = 44eb98d`, der Tag `v0.1.3` zeigt
auf `1fb556f`.

Für ein Werkzeug, dessen Zweck Nachvollziehbarkeit ist, ist das das schlechteste
mögliche Ergebnis — schlechter als ein roter Lauf, weil es grün aussieht.
Entscheidung:

* Im Skip-Pfad wird npms `gitHead` gegen `$GITHUB_SHA` verglichen. Abweichung →
  **Abbruch** mit der Anweisung, die Version zu erhöhen statt den Tag zu
  verschieben.
* Lässt sich `gitHead` nicht lesen, ist die Gleichheit **nicht bewiesen** und das
  ist derselbe Abbruch. „Nicht prüfbar" heißt hier nicht „wahrscheinlich in
  Ordnung" — dieselbe Regel, die die Readiness-Checkliste auf sich selbst
  anwendet (§6.5).
* **Eine veröffentlichte Version ist endgültig.** Tags werden nicht verschoben.

**Drittens, eine verwandte Reihenfolge.** Die beiden Selbst-Scans laufen mit
`|| true`, weil ein Finding über der Schwelle kein kaputtes Release ist. Ein
Absturz sieht am Exit-Code identisch aus. Die Evidenzdateien werden deshalb auf
Existenz geprüft — und zwar **im Scan-Schritt, vor dem Publish**. Vorher fiel ein
fehlendes SBOM erst beim Upload auf, also nachdem die Version auf der Registry
war.

## 15. Randfälle der Lockfile-Parser — und die Regel dahinter

### 15.1 Die Regel

Ein Lockfile enthält Formen, die eine SBOM nicht exakt ausdrücken kann: ein Paket
unter einem anderen Namen installiert, aus einem git-Commit gebaut, aus einem
Verzeichnis vendort, vom Paketmanager gepatcht.

Die Regel ist **nicht** „alles unterstützen". Sie ist: **nichts stillschweigend
verwerfen.** Eine übersprungene Abhängigkeit hinterlässt eine Ausgabe, die
weiterhin vollständig *aussieht* — die Komponentenliste ist plausibel, die
Finding-Zahl liest sich wie eine Antwort, und nichts sagt, dass ein Paket fehlt.
Das ist strikt schlechter als es zu sagen, aus demselben Grund, aus dem die
Readiness-Checkliste „nicht prüfbar" meldet statt eines zuversichtlichen leeren
Felds (§6.5).

Umgesetzt als `ResolveNote` mit `kind`, `subject`, `message` und `hint`. Jede Note
steht in der Konsolenausgabe, in `findings.json` (damit eine Maschine dieselben
Vorbehalte sieht wie ein Mensch) und im Report als eigener Abschnitt **vor** der
Komponententabelle: alles darüber ist eine Zahl, und eine Zahl kann nicht sagen,
dass eines der gezählten Dinge nicht ganz das ist, wonach es aussieht. Bei einem
gewöhnlichen Projekt fehlt der Abschnitt vollständig, damit seine Anwesenheit
etwas bedeutet.

Sechs Arten: `git-dependency`, `local-dependency`, `aliased-dependency`,
`patched-dependency`, `unresolved-dependency`, `bundled-dependency`.

### 15.2 Entscheidung: der veröffentlichte Name gewinnt

Bei einem `npm:`-Alias (`"is-alias": "npm:@sindresorhus/is@^7.0.1"`) trägt die
Komponente **`@sindresorhus/is`**, nicht `is-alias`. Begründung: OSV schlüsselt
Advisories nach dem veröffentlichten Namen, und eine purl auf `is-alias` würde ein
Paket benennen, das es nicht gibt. Der Alias-Name erscheint dadurch nirgends in
der Ausgabe — genau deshalb gibt es die Note.

### 15.3 Gefundene Fehler

Die folgenden waren echt und sind behoben. Sie stehen hier vollständig, weil jeder
einzelne dieselbe Signatur hatte: eine plausibel aussehende Ausgabe.

**npm**

* Eine `file:`-Abhängigkeit wurde als **Workspace** geführt. Beide werden
  außerhalb von `node_modules` materialisiert und ihre Lockfile-Einträge sind
  nicht unterscheidbar; nur der deklarierte Range trennt sie. Folge: fremder Code
  stand in der Workspace-Liste als eigenes Paket des Produkts.
* Eine deklarierte, aber in der Lockfile fehlende Abhängigkeit verschwand
  wortlos.

**pnpm**

* Eine git-Abhängigkeit bekam eine **URL als Version** —
  `pkg:npm/left-pad@https://codeload.github.com/…`. Der Key trägt bei pnpm die
  Tarball-URL; die echte Version steht in einem eigenen Feld.
* Eine `file:`-Abhängigkeit bekam den **Spezifikator als Version** —
  `pkg:npm/acme-local-lib@file:local-lib`. Bei `type: directory` steht die Version
  nirgends in der Lockfile; sie kommt jetzt aus der `package.json` des
  Verzeichnisses. Ist sie auch dort nicht lesbar, wird die Komponente
  weggelassen **und gemeldet**, nicht erfunden.
* Monorepos waren flachgeklopft und ihre Mitglieder unerreichbar (§14.1 unten,
  gefunden durch den Corpus).

**Yarn (beide)**

* `splitDescriptor` teilte am **letzten** `@`. Richtig ist der **erste** nach
  Position 0, weil ein Scope-`@` auf Position 0 sitzt und der Range danach
  beliebig viele weitere enthalten darf. Ergebnis vorher: Namen wie
  `typescript@patch:typescript`.
* Berry nahm den Namen aus dem Descriptor statt aus `resolution`. Bei einem Alias
  weichen sie ab, und es entstand eine Komponente `is-alias` mit einer purl für
  ein nicht existierendes Paket.
* Berry behandelte `linkType: soft` als „ist ein Workspace". Das gilt auch für
  `portal:` und `link:`, die damit aus der SBOM fielen und anschließend als „nicht
  in der Lockfile" gemeldet wurden — obwohl sie sichtbar darin standen. Maßgeblich
  ist ausschließlich eine `@workspace:`-Resolution.
* Berry speicherte Descriptors nur protokoll-gestrippt. Für einen Alias ist die
  gestrippte Form bedeutungslos, also löste er nie auf. Jetzt werden beide
  Schreibweisen registriert, zusätzlich die ohne `::locator=`-Suffix.
* Yarns eingebaute `patch:`-Einträge wurden lautlos verworfen. Sie bleiben
  **eine** Komponente (zwei wären Doppelzählung), aber mit Note: der Code auf der
  Platte ist nicht der veröffentlichte.
* Yarn Classic erkannte git und `file:` überhaupt nicht, weil nur Berrys
  `resolution` gelesen wurde. Classic hat kein solches Feld; die Erkennung liest
  jetzt den Descriptor-Range.

**Gemeinsam**

* Eine **optionale Root-Abhängigkeit** war als `prod` gelabelt. Der
  `optional`-Kind galt nur für Paket-Kanten, nicht für die des Roots — CycloneDX
  hat `scope: optional`, und die Information ging verloren.

### 15.4 Was bewusst nicht gemeldet wird

Eine **unerfüllte optionale Abhängigkeit**. Das ist der Normalfall und
funktionierendes Verhalten des Paketmanagers; sie zu melden würde die Notes
entwerten, die tatsächlich etwas bedeuten.

### 15.5 Private Registries

Die Tarball-URL landet in `externalReferences` und **nirgends sonst**. Nicht in
der purl, nicht in einem Hash-Feld. Eine purl, die einen internen Host und ein
Token einbettet, wäre keine gültige purl — und würde die Registry in jede SBOM
tragen, die an einen Dritten geht. Ein Test hält das fest.
