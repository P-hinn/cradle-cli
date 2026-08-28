/**
 * The report stylesheet, inlined into the document.
 *
 * Three constraints shape it. The file has to stand on its own, so there are no
 * webfonts and no external assets. It has to print, because that is how audit
 * evidence still travels. And severity may never be carried by colour alone —
 * every severity is spelled out in text and repeated as a shape, so the document
 * works in greyscale and for a reader who cannot distinguish red from green.
 */
export const REPORT_CSS = `
:root {
  --ink: #14171a;
  --ink-soft: #4a5158;
  --ink-faint: #6b737b;
  --rule: #d8dce0;
  --rule-strong: #b4bbc2;
  --surface: #ffffff;
  --surface-sunken: #f5f6f8;
  --accent: #1f4e79;
  --critical: #7a1020;
  --high: #a33a10;
  --medium: #7a5a00;
  --low: #3b5a3f;
  --none: #4a5158;
  --unknown: #4a5158;
}

* { box-sizing: border-box; }

html { -webkit-text-size-adjust: 100%; }

body {
  margin: 0;
  padding: 0 1.5rem 4rem;
  background: var(--surface);
  color: var(--ink);
  font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}

.wrap { max-width: 1080px; margin: 0 auto; }

code, .mono, th.num, td.num {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  font-size: 0.92em;
}

a { color: var(--accent); text-decoration: underline; text-underline-offset: 2px; }
a:focus-visible, button:focus-visible, input:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}

/* ---------- masthead ---------- */

header.masthead {
  border-bottom: 3px solid var(--ink);
  padding: 2.5rem 0 1.25rem;
  margin-bottom: 1.75rem;
}

.eyebrow {
  font-size: 0.75rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--ink-faint);
  margin: 0 0 0.4rem;
}

h1 { font-size: 1.85rem; line-height: 1.2; margin: 0 0 0.15rem; font-weight: 650; }
h1 .version { color: var(--ink-soft); font-weight: 400; }

h2 {
  font-size: 1.15rem;
  margin: 2.75rem 0 0.4rem;
  padding-bottom: 0.35rem;
  border-bottom: 1px solid var(--rule-strong);
  font-weight: 650;
}

h2 .count { color: var(--ink-faint); font-weight: 400; font-size: 0.9rem; }

.section-note { color: var(--ink-soft); font-size: 0.88rem; margin: 0.5rem 0 1rem; }

/* Scan provenance: what was scanned, when, by what. An auditor reads this first. */
dl.facts {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(9.5rem, 1fr));
  gap: 0.9rem 1.5rem;
  margin: 1.25rem 0 0;
}
dl.facts dt {
  font-size: 0.72rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--ink-faint);
  margin-bottom: 0.15rem;
}
dl.facts dd { margin: 0; font-size: 0.9rem; word-break: break-word; }

.banner {
  border: 1px solid var(--rule-strong);
  border-left: 4px solid var(--medium);
  background: var(--surface-sunken);
  padding: 0.7rem 0.9rem;
  margin: 1.25rem 0 0;
  font-size: 0.9rem;
}
.banner strong { font-weight: 650; }

/* ---------- summary ---------- */

.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr));
  gap: 0.75rem;
  margin: 1rem 0 0;
}
.card {
  border: 1px solid var(--rule);
  padding: 0.85rem 0.95rem;
  background: var(--surface);
}
.card .label {
  font-size: 0.72rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--ink-faint);
}
.card .value { font-size: 1.7rem; line-height: 1.15; margin-top: 0.2rem; font-weight: 600; }
.card .detail { font-size: 0.83rem; color: var(--ink-soft); margin-top: 0.2rem; }

/* Severity totals. The bar is decoration; the number and the word carry it. */
.sev-list { list-style: none; margin: 1rem 0 0; padding: 0; display: grid; gap: 0.35rem; }
.sev-list li { display: grid; grid-template-columns: 8.5rem 3rem 1fr; align-items: center; gap: 0.6rem; }
.sev-list .bar { height: 0.6rem; background: var(--surface-sunken); border: 1px solid var(--rule); }
.sev-list .bar span { display: block; height: 100%; background: var(--ink-soft); }

/* ---------- severity marks ---------- */

.sev {
  display: inline-flex;
  align-items: baseline;
  gap: 0.4rem;
  font-size: 0.78rem;
  font-weight: 650;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  white-space: nowrap;
}
/* The glyph repeats the severity as a shape, so the meaning survives greyscale
   printing and colour-blind readers. */
.sev::before {
  content: attr(data-glyph);
  font-family: ui-monospace, monospace;
  font-size: 0.9em;
  letter-spacing: -0.05em;
}
.sev-critical { color: var(--critical); }
.sev-high { color: var(--high); }
.sev-medium { color: var(--medium); }
.sev-low { color: var(--low); }
.sev-none, .sev-unknown { color: var(--none); }

.status {
  display: inline-flex;
  align-items: baseline;
  gap: 0.35rem;
  font-size: 0.78rem;
  font-weight: 650;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  white-space: nowrap;
}
/* Same rule as severity: the glyph repeats the meaning as a shape. */
.status::before {
  content: attr(data-glyph);
  font-family: ui-monospace, monospace;
}
.status-met { color: var(--low); }
.status-partial { color: var(--medium); }
.status-open { color: var(--high); }
.status-not-assessable { color: var(--ink-faint); }

tr.ready-open > td:first-child { border-left: 3px solid var(--high); }
tr.ready-partial > td:first-child { border-left: 3px solid var(--medium); }

.tag {
  display: inline-block;
  border: 1px solid var(--rule-strong);
  padding: 0.05rem 0.35rem;
  font-size: 0.72rem;
  letter-spacing: 0.04em;
  color: var(--ink-soft);
  white-space: nowrap;
}

/* ---------- controls ---------- */

.controls {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem 0.75rem;
  align-items: center;
  margin: 0 0 0.75rem;
  padding: 0.65rem 0.75rem;
  background: var(--surface-sunken);
  border: 1px solid var(--rule);
}
.controls input[type="search"] {
  flex: 1 1 14rem;
  min-width: 0;
  font: inherit;
  font-size: 0.9rem;
  padding: 0.35rem 0.5rem;
  border: 1px solid var(--rule-strong);
  background: var(--surface);
  color: inherit;
}
.controls label { font-size: 0.85rem; display: inline-flex; align-items: center; gap: 0.3rem; }
.controls .spacer { flex: 1 1 auto; }
.controls .result-count { font-size: 0.83rem; color: var(--ink-soft); }

/* ---------- tables ---------- */

.scroll { overflow-x: auto; }

table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th, td { text-align: left; padding: 0.5rem 0.6rem; border-bottom: 1px solid var(--rule); vertical-align: top; }
thead th {
  border-bottom: 2px solid var(--rule-strong);
  font-size: 0.72rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--ink-faint);
  font-weight: 650;
  white-space: nowrap;
}
th.sortable { cursor: pointer; user-select: none; }
th.sortable::after { content: " \\2195"; color: var(--rule-strong); }
th.sortable[aria-sort="ascending"]::after { content: " \\2191"; color: var(--ink); }
th.sortable[aria-sort="descending"]::after { content: " \\2193"; color: var(--ink); }

tbody tr.detail-row > td { border-bottom: 1px solid var(--rule); background: var(--surface-sunken); }
tbody tr[hidden] { display: none; }

.pathline { font-size: 0.82rem; color: var(--ink-soft); margin-top: 0.2rem; }
.pathline .sep { color: var(--rule-strong); padding: 0 0.15rem; }

button.disclose {
  font: inherit;
  font-size: 0.8rem;
  background: none;
  border: 1px solid var(--rule-strong);
  padding: 0.1rem 0.4rem;
  cursor: pointer;
  color: var(--ink-soft);
}

.detail-grid { display: grid; grid-template-columns: 7rem 1fr; gap: 0.35rem 0.9rem; font-size: 0.87rem; }
.detail-grid dt { color: var(--ink-faint); }
.detail-grid dd { margin: 0; word-break: break-word; }
.detail-grid ul { margin: 0; padding-left: 1.1rem; }

.sr-only {
  position: absolute;
  width: 1px; height: 1px;
  padding: 0; margin: -1px;
  overflow: hidden;
  clip: rect(0 0 0 0);
  white-space: nowrap;
  border: 0;
}

.empty { padding: 1.25rem; border: 1px dashed var(--rule-strong); color: var(--ink-soft); font-size: 0.9rem; }

/* ---------- footer ---------- */

footer.colophon {
  margin-top: 3.5rem;
  padding-top: 1rem;
  border-top: 1px solid var(--rule-strong);
  font-size: 0.82rem;
  color: var(--ink-soft);
}
footer.colophon p { margin: 0 0 0.5rem; max-width: 60ch; }

/* ---------- print ---------- */

@media print {
  body { padding: 0; font-size: 10.5pt; }
  .controls, button.disclose { display: none !important; }
  /* Everything filtering hid comes back: a printed report must be complete. */
  tbody tr[hidden] { display: table-row !important; }
  thead { display: table-header-group; }
  tr, .card { break-inside: avoid; }
  h2 { break-after: avoid; }
  a { color: inherit; text-decoration: none; }
  /* Links are useless on paper unless the target is spelled out. */
  .detail-grid a::after { content: " (" attr(href) ")"; font-size: 0.85em; color: var(--ink-faint); word-break: break-all; }
}
`
