/**
 * Renders assets/demo.svg from a recorded cradle session.
 *
 * A static SVG rather than a GIF or an asciinema embed: it is a single file in
 * the repository, it costs no third-party request, it stays sharp at any size,
 * and the text in it is real — captured from an actual run against
 * examples/express-service, not typed out to look good.
 *
 * Spaces become non-breaking ones, because SVG collapses runs of whitespace and
 * xml:space="preserve" is not honoured consistently. In a monospace font the two
 * are the same width, and the column alignment is most of what makes the output
 * legible.
 *
 *   node scripts/gen-demo-svg.mjs
 */
import { readFileSync, writeFileSync } from 'node:fs'

const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))

/** A dark card reads the same under GitHub's light and dark themes. */
const THEME = {
  background: '#12161b',
  chrome: '#1b2129',
  border: '#2b333d',
  text: '#c9d3de',
  dim: '#7d8b99',
  prompt: '#5aa9e6',
  command: '#e6edf3',
  critical: '#f47c7c',
  high: '#f0a868',
  medium: '#e2c275',
  ok: '#8fce9b',
  accent: '#9ecbff',
}

const FONT =
  'ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace'

const LINE_HEIGHT = 19
const CHAR_WIDTH = 8.02
const PADDING_X = 20
const CHROME_HEIGHT = 34

/**
 * The session, exactly as it was printed. `style` picks a colour; `null` is the
 * ordinary body text.
 */
const SESSION = [
  { text: '$ npx cradle-cli scan', style: 'command' },
  { text: '', style: null },
  {
    text: `cradle ${version} · acme-express-service 2.1.0 · npm · production only`,
    style: 'dim',
  },
  { text: '', style: null },
  { text: '  Components   4 (3 direct, 1 transitive)', style: null },
  { text: '  Licences     4 known, 0 unknown', style: null },
  { text: '  Findings     8 (1 critical, 3 high, 4 medium)', style: 'high' },
  { text: '  CRA checks   4 met, 2 partial', style: null },
  { text: '  Report       .cradle/report.html', style: 'accent' },
  { text: '  Output       .cradle/ · CycloneDX 1.6', style: null },
  { text: '', style: null },
  { text: '  Next steps', style: null },
  {
    text: '    · minimist 1.2.0 -> 1.2.6  (clears 2 findings, worst critical, direct)',
    style: 'dim',
  },
  {
    text: '    · lodash 4.17.15 -> 4.18.0  (clears 6 findings, worst high, direct)',
    style: 'dim',
  },
  { text: '', style: null },
  { text: '$ npx cradle-cli check --fail-on high', style: 'command' },
  { text: '', style: null },
  { text: '  New since the baseline', style: null },
  { text: '    critical GHSA-xvch-5gv4-984h  minimist 1.2.0  (fix in 1.2.6)', style: 'critical' },
  { text: '    high     GHSA-35jh-r3h4-6jhm  lodash 4.17.15  (fix in 4.17.21)', style: 'high' },
  { text: '    high     GHSA-p6mc-m468-83gw  lodash 4.17.15  (fix in 4.17.19)', style: 'high' },
  { text: '    …', style: 'dim' },
  { text: '', style: null },
  { text: '  Failing: 4 new findings at or above high.', style: 'critical' },
  { text: '', style: null },
  { text: '$ echo $?', style: 'command' },
  { text: '1', style: null },
]

const width = Math.round(
  PADDING_X * 2 + CHAR_WIDTH * Math.max(...SESSION.map((line) => line.text.length)),
)
const height = CHROME_HEIGHT + 14 + SESSION.length * LINE_HEIGHT + 14

function escapeXml(value) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/ /g, '&#160;')
}

const rows = SESSION.map((line, index) => {
  const y = CHROME_HEIGHT + 14 + (index + 1) * LINE_HEIGHT - 5
  if (line.text === '') return ''

  if (line.style === 'command') {
    const command = line.text.slice(2)
    return (
      `  <text x="${PADDING_X}" y="${y}" fill="${THEME.prompt}">$</text>` +
      `<text x="${PADDING_X + CHAR_WIDTH * 2}" y="${y}" fill="${THEME.command}">${escapeXml(command)}</text>`
    )
  }
  const fill = line.style === null ? THEME.text : THEME[line.style]
  return `  <text x="${PADDING_X}" y="${y}" fill="${fill}">${escapeXml(line.text)}</text>`
}).filter(Boolean)

const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-label="Terminal session: npx cradle-cli scan reports 4 components and 8 findings, then npx cradle-cli check exits 1 on findings above the threshold.">
  <rect width="${width}" height="${height}" rx="8" fill="${THEME.background}" stroke="${THEME.border}"/>
  <path d="M0 8 a8 8 0 0 1 8 -8 h${width - 16} a8 8 0 0 1 8 8 v${CHROME_HEIGHT - 8} h-${width} z" fill="${THEME.chrome}"/>
  <line x1="0" y1="${CHROME_HEIGHT}" x2="${width}" y2="${CHROME_HEIGHT}" stroke="${THEME.border}"/>
  <circle cx="20" cy="17" r="5" fill="#e06c62"/>
  <circle cx="38" cy="17" r="5" fill="#e0b562"/>
  <circle cx="56" cy="17" r="5" fill="#7fc08a"/>
  <text x="${width / 2}" y="21" text-anchor="middle" font-family="${FONT}" font-size="11" fill="${THEME.dim}">acme-express-service</text>
  <g font-family="${FONT}" font-size="13">
${rows.join('\n')}
  </g>
</svg>
`

writeFileSync(new URL('../assets/demo.svg', import.meta.url), svg)
console.log(`wrote assets/demo.svg (${width}x${height})`)
