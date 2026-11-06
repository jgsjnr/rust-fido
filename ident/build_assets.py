"""Rebuild original vector assets and the documentation inventory, without dependencies."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ASSETS = ROOT / 'assets'
ASSETS.mkdir(exist_ok=True)
MARK = '<path d="M32 4 56 14v21c0 14-24 25-24 25S8 49 8 35V14z"/><path d="m19 40 13-25 13 25M24 31h16"/><circle cx="32" cy="41" r="2" fill="currentColor" stroke="none"/>'


def write(name, content):
    (ASSETS / name).write_text(content, encoding='utf-8')


def symbol(color):
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none" stroke="{color}" color="{color}" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><title>AegisKey — símbolo</title>{MARK}</svg>'


for name, color in [('symbol.svg', '#9ecaff'), ('symbol-dark.svg', '#001d36'), ('symbol-mono.svg', '#ffffff')]:
    write(name, symbol(color))

# Wordmark uses original vector outlines rather than a font dependency.
LETTERS = {
    'A': 'M0 30 10 0 20 30M4 20h12',
    'E': 'M20 0H0v30h20M0 15h16',
    'G': 'M20 5Q15 0 10 0Q0 0 0 15t10 15h10V16H11',
    'I': 'M4 0v30',
    'S': 'M20 3Q15 0 10 0Q0 0 0 8q0 7 10 7t10 8q0 7-10 7Q4 30 0 27',
    'K': 'M0 0v30M20 0 0 17m8-7 13 20',
    'Y': 'M0 0 10 15 20 0M10 15v15',
}
word = []
x = 83
for letter in 'AEGISKEY':
    word.append(f'<path transform="translate({x} 19)" d="{LETTERS[letter]}"/>')
    x += 18 if letter == 'I' else 29
for name, color in [('logo-horizontal.svg', '#9ecaff'), ('logo-horizontal-dark.svg', '#001d36'), ('logo-horizontal-mono.svg', '#ffffff')]:
    write(name, f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 320 64" fill="none" stroke="{color}" color="{color}" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><title>AegisKey — assinatura horizontal vetorial</title>{MARK}{"".join(word)}</svg>')
write('app-icon.svg', f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128"><title>AegisKey — app icon</title><rect width="128" height="128" rx="29" fill="#00497d"/><g transform="translate(25 24) scale(1.22)" fill="none" stroke="#9ecaff" color="#9ecaff" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round">{MARK}</g></svg>')
write('tray.svg', symbol('#ffffff'))
write('device-concept.svg', '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 360 260" fill="none">
<title>AegisKey — conceito visual de produto, sem especificação física</title>
<defs><linearGradient id="body" x1="70" y1="75" x2="300" y2="180" gradientUnits="userSpaceOnUse"><stop stop-color="#485657"/><stop offset=".2" stop-color="#2c393b"/><stop offset=".6" stop-color="#1b2729"/><stop offset="1" stop-color="#39484a"/></linearGradient><linearGradient id="metal" x1="0" x2="1"><stop stop-color="#6f807f"/><stop offset=".4" stop-color="#c5d1cc"/><stop offset="1" stop-color="#667875"/></linearGradient></defs>
<path d="m69 101 218-8 10 71-218 7z" fill="#0a1316" stroke="#617571"/>
<rect x="29" y="108" width="68" height="47" rx="4" fill="url(#metal)" stroke="#97a8a2"/>
<path d="M35 117h48v28H35z" fill="#384746" stroke="#7f918b"/><path d="M41 123h32v15H41z" fill="#192827"/><path d="M44 125v11m6-11v11m6-11v11m6-11v11m6-11v11" stroke="#9b9a77" stroke-width="2"/>
<path d="M81 95h202q15 0 15 15v44q0 15-15 15H81q-10 0-10-10v-54q0-10 10-10" fill="url(#body)" stroke="#718581"/>
<path d="M80 103h195q13 0 13 12v34q0 12-13 12H80" stroke="#72847f" stroke-opacity=".3"/>
<path d="M101 107v50m4-50v50" stroke="#152321"/>
<rect x="115" y="111" width="4" height="37" rx="2" fill="#9ecaff"/><rect x="114" y="112" width="6" height="34" rx="3" fill="#9ecaff" opacity=".2"/>
<g transform="translate(143 111) scale(.57)" stroke="#b6c9c3" color="#b6c9c3" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round">''' + MARK + '''</g>
<path d="M197 121h48m-48 8h34m-34 9h42" stroke="#738b83" stroke-width="2"/>
<circle cx="273" cy="133" r="8" fill="#142121" stroke="#718982"/><circle cx="273" cy="133" r="4" stroke="#071410"/>
<path d="M82 170h199" stroke="#050e10" stroke-width="3"/>
</svg>''')
js = (ROOT / 'app.js').read_text(encoding='utf-8')
icons = re.findall(r"^ (\w+):'([^']+)'", js, re.M)
symbols = []
for name, body in icons:
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><title>{name}</title>{body}</svg>'
    write(f'icon-{name}.svg', svg)
    symbols.append(f'<symbol id="{name}" viewBox="0 0 24 24"><g fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">{body}</g></symbol>')
write('icons.svg', '<svg xmlns="http://www.w3.org/2000/svg"><defs>' + ''.join(symbols) + '</defs></svg>')

# Structural scan of every tracked Markdown file; this is not a claim of a line-by-line audit.
repo = ROOT.parent
tracked = subprocess.check_output(['git', 'ls-files', '*.md'], cwd=repo, text=True, encoding='utf-8').splitlines()
inventory = []
for relative in tracked:
    path = repo / relative
    if not path.is_file():
        continue
    text = path.read_text(encoding='utf-8', errors='replace')
    inventory.append({'path': relative, 'lines': len(text.splitlines()), 'headings': re.findall(r'^#{1,3} (.+)', text, re.M), 'topics': [topic for topic in ['Secure Guard','WebAuthn','TOTP','OpenSSH','Shamir','Password','proximity','eFuse','OTA'] if topic.casefold() in text.casefold()]})
(ROOT / 'documentation-inventory.json').write_text(json.dumps({'method': 'Structural inventory of tracked Markdown, with topic scan; focused reading is described in ANALISE.md.', 'commit': subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),'documents': inventory}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'Generated {len(list(ASSETS.glob("*.svg")))} vector assets; indexed {len(inventory)} Markdown files.')
