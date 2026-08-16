#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const JSZip = require('jszip');

const VERSION = 'dirextalk-presentation 1.0.0';
const EMU_PER_INCH = 914400;
const POINTS_PER_INCH = 72;

const GUIDE = `Official Pi Worker presentation workflow

Create native, editable PowerPoint files with PptxGenJS and qualify the rendered result before submitting it.

1. Write a CommonJS module that exports one async function:

   module.exports = async ({ pptxgen, output }) => {
     const pptx = new pptxgen();
     pptx.layout = 'LAYOUT_WIDE';
     pptx.author = 'Dirextalk Pi Worker';
     // Add slides, text, charts, shapes, tables, and images here.
     await pptx.writeFile({ fileName: output });
   };

2. Build and visually qualify it:

   dirextalk-presentation build deck.cjs deck.pptx --qa-dir deck-qa --strict

3. Inspect deck-qa/presentation-qa.json and deck-qa/preview.png. Fix every reported overflow, off-slide object, or unintended text overlap. Re-run until PASS.

4. Return the editable .pptx, preview.png, presentation-qa.json, and useful source/input files as deliverables. Do not claim visual verification unless this command passed.

Design defaults: 16:9 layout, readable body text (normally 18pt or larger), high contrast, concise text, stable margins, and one clear visual hierarchy per slide. Use real images when supplied or authorized; do not invent factual citations or data.`;

function fail(message, code = 64) {
  process.stderr.write(`${message}\n`);
  process.exit(code);
}

function usage() {
  fail('usage: dirextalk-presentation version|guide|build SCRIPT OUTPUT [--qa-dir DIR] [--strict]|verify PPTX [--qa-dir DIR] [--strict]');
}

function resolveInsideWorkspace(value, label) {
  if (!value || value.includes('\0')) fail(`${label} is required`);
  const root = fs.realpathSync(process.cwd());
  const resolved = path.resolve(root, value);
  if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) {
    fail(`${label} must stay inside the current workspace`);
  }
  return resolved;
}

function parseOptions(values) {
  let qaDir;
  let strict = false;
  for (let index = 0; index < values.length; index += 1) {
    switch (values[index]) {
      case '--qa-dir':
        index += 1;
        if (index >= values.length) usage();
        qaDir = resolveInsideWorkspace(values[index], 'QA directory');
        break;
      case '--strict':
        strict = true;
        break;
      default:
        usage();
    }
  }
  return { qaDir, strict };
}

function findExecutable(candidates) {
  for (const candidate of candidates) {
    if (candidate.includes(path.sep)) {
      if (fs.existsSync(candidate)) return candidate;
      continue;
    }
    try {
      return execFileSync('/bin/sh', ['-c', 'command -v "$1"', 'sh', candidate], { encoding: 'utf8' }).trim();
    } catch (_) {
      // Keep looking.
    }
  }
  return '';
}

function decodeXML(value) {
  return value
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function shapeMetrics(xml, slideWidth, slideHeight, slideNumber) {
  const warnings = [];
  const shapes = [];
  const shapePattern = /<p:sp(?:\s[^>]*)?>([\s\S]*?)<\/p:sp>/g;
  let match;
  while ((match = shapePattern.exec(xml)) !== null) {
    const body = match[1];
    const off = body.match(/<a:off\s+x="(-?\d+)"\s+y="(-?\d+)"\s*\/>/);
    const ext = body.match(/<a:ext\s+cx="(\d+)"\s+cy="(\d+)"\s*\/>/);
    const text = [...body.matchAll(/<a:t>([\s\S]*?)<\/a:t>/g)].map((item) => decodeXML(item[1])).join('');
    if (!off || !ext || !text.trim()) continue;
    const x = Number(off[1]);
    const y = Number(off[2]);
    const width = Number(ext[1]);
    const height = Number(ext[2]);
    const fontSizes = [...body.matchAll(/\ssz="(\d+)"/g)].map((item) => Number(item[1]) / 100);
    const fontSize = fontSizes.length ? Math.max(...fontSizes) : 18;
    const shape = { x, y, width, height, text: text.trim(), fontSize };
    shapes.push(shape);

    if (x < 0 || y < 0 || x + width > slideWidth || y + height > slideHeight) {
      warnings.push(`slide ${slideNumber}: text box extends beyond the slide: ${shape.text.slice(0, 80)}`);
    }
    const widthPoints = (width / EMU_PER_INCH) * POINTS_PER_INCH;
    const heightPoints = (height / EMU_PER_INCH) * POINTS_PER_INCH;
    const cjk = (shape.text.match(/[\u2e80-\u9fff\uf900-\ufaff]/g) || []).length;
    const weightedCharacters = cjk + (shape.text.length - cjk) * 0.54;
    const charactersPerLine = Math.max(1, widthPoints / Math.max(1, fontSize));
    const estimatedLines = Math.max(1, Math.ceil(weightedCharacters / charactersPerLine));
    const availableLines = Math.max(1, Math.floor(heightPoints / Math.max(1, fontSize * 1.25)));
    if (estimatedLines > availableLines + 1) {
      warnings.push(`slide ${slideNumber}: possible text overflow (${estimatedLines} estimated lines for ${availableLines} available): ${shape.text.slice(0, 80)}`);
    }
  }

  for (let left = 0; left < shapes.length; left += 1) {
    for (let right = left + 1; right < shapes.length; right += 1) {
      const a = shapes[left];
      const b = shapes[right];
      const overlapWidth = Math.max(0, Math.min(a.x + a.width, b.x + b.width) - Math.max(a.x, b.x));
      const overlapHeight = Math.max(0, Math.min(a.y + a.height, b.y + b.height) - Math.max(a.y, b.y));
      const overlap = overlapWidth * overlapHeight;
      const smaller = Math.min(a.width * a.height, b.width * b.height);
      if (smaller > 0 && overlap / smaller > 0.12) {
        warnings.push(`slide ${slideNumber}: possible text overlap: "${a.text.slice(0, 42)}" / "${b.text.slice(0, 42)}"`);
      }
    }
  }
  return warnings;
}

async function inspectPackage(pptxPath) {
  const bytes = fs.readFileSync(pptxPath);
  const zip = await JSZip.loadAsync(bytes, { checkCRC32: true });
  const presentationEntry = zip.file('ppt/presentation.xml');
  if (!presentationEntry) throw new Error('ppt/presentation.xml is missing');
  const presentationXML = await presentationEntry.async('string');
  const size = presentationXML.match(/<p:sldSz\s+cx="(\d+)"\s+cy="(\d+)"/);
  if (!size) throw new Error('slide dimensions are missing');
  const slideWidth = Number(size[1]);
  const slideHeight = Number(size[2]);
  const entries = Object.keys(zip.files)
    .filter((name) => /^ppt\/slides\/slide\d+\.xml$/.test(name))
    .sort((left, right) => Number(left.match(/\d+/)[0]) - Number(right.match(/\d+/)[0]));
  if (entries.length === 0) throw new Error('presentation contains no slides');
  const warnings = [];
  const texts = [];
  for (let index = 0; index < entries.length; index += 1) {
    const xml = await zip.file(entries[index]).async('string');
    warnings.push(...shapeMetrics(xml, slideWidth, slideHeight, index + 1));
    texts.push(...[...xml.matchAll(/<a:t>([\s\S]*?)<\/a:t>/g)]
      .map((item) => decodeXML(item[1]).trim())
      .filter((value) => value.length > 1));
  }
  return { slideCount: entries.length, slideWidth, slideHeight, warnings, texts };
}

function renderPresentation(pptxPath, qaDir, expectedSlides) {
  const soffice = findExecutable([
    process.env.DIREXTALK_SOFFICE || '',
    '/opt/libreoffice25.8/program/soffice',
    'libreoffice',
    'soffice',
  ].filter(Boolean));
  const pdfinfo = findExecutable(['pdfinfo']);
  const pdftoppm = findExecutable(['pdftoppm']);
  const pdftotext = findExecutable(['pdftotext']);
  if (!soffice || !pdfinfo || !pdftoppm || !pdftotext) {
    throw new Error('LibreOffice and Poppler rendering tools are required');
  }
  fs.mkdirSync(qaDir, { recursive: true, mode: 0o700 });
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'dirextalk-presentation-lo-'));
  try {
    execFileSync(soffice, [
      '--headless', '--nologo', '--nodefault', '--nolockcheck', '--norestore',
      `-env:UserInstallation=file://${profile}`,
      '--convert-to', 'pdf', '--outdir', qaDir, pptxPath,
    ], { stdio: 'pipe', timeout: 120000 });
  } finally {
    fs.rmSync(profile, { recursive: true, force: true });
  }
  const pdfPath = path.join(qaDir, `${path.basename(pptxPath, '.pptx')}.pdf`);
  if (!fs.existsSync(pdfPath) || fs.statSync(pdfPath).size === 0) {
    throw new Error('LibreOffice did not produce a PDF render');
  }
  const info = execFileSync(pdfinfo, [pdfPath], { encoding: 'utf8', timeout: 30000 });
  const pageMatch = info.match(/^Pages:\s+(\d+)$/m);
  const pages = pageMatch ? Number(pageMatch[1]) : 0;
  if (pages !== expectedSlides) {
    throw new Error(`rendered page count ${pages} does not match slide count ${expectedSlides}`);
  }
  const prefix = path.join(qaDir, 'slide');
  execFileSync(pdftoppm, ['-png', '-r', '120', pdfPath, prefix], { stdio: 'pipe', timeout: 120000 });
  const images = fs.readdirSync(qaDir)
    .filter((name) => /^slide-\d+\.png$/.test(name))
    .sort((left, right) => Number(left.match(/\d+/)[0]) - Number(right.match(/\d+/)[0]))
    .map((name) => path.join(qaDir, name));
  if (images.length !== expectedSlides) {
    throw new Error(`rendered image count ${images.length} does not match slide count ${expectedSlides}`);
  }
  const renderedText = execFileSync(pdftotext, ['-layout', pdfPath, '-'], { encoding: 'utf8', timeout: 30000 });
  return { pdfPath, images, renderedText, soffice, pdfinfo, pdftoppm, pdftotext };
}

function normalizedRenderedText(value) {
  return value.normalize('NFKC').replace(/\s+/gu, '');
}

async function verify(pptxPath, qaDir, strict) {
  if (path.extname(pptxPath).toLowerCase() !== '.pptx') fail('input must be a .pptx file');
  if (!fs.existsSync(pptxPath) || !fs.statSync(pptxPath).isFile() || fs.statSync(pptxPath).size === 0) {
    fail('PPTX file is missing or empty');
  }
  fs.rmSync(qaDir, { recursive: true, force: true });
  fs.mkdirSync(qaDir, { recursive: true, mode: 0o700 });
  const inspected = await inspectPackage(pptxPath);
  const rendered = renderPresentation(pptxPath, qaDir, inspected.slideCount);
  const renderedText = normalizedRenderedText(rendered.renderedText);
  for (const value of inspected.texts) {
    if (!renderedText.includes(normalizedRenderedText(value))) {
      inspected.warnings.push(`rendered PDF is missing text (font or layout failure): ${value.slice(0, 100)}`);
    }
  }
  const previewPath = path.join(qaDir, 'preview.png');
  fs.copyFileSync(rendered.images[0], previewPath);
  const report = {
    schema_version: 'dirextalk.agent.presentation-qa/v1',
    status: strict && inspected.warnings.length ? 'failed' : 'passed',
    pptx: path.basename(pptxPath),
    slides: inspected.slideCount,
    rendered_pages: rendered.images.length,
    preview: path.basename(previewPath),
    pdf: path.basename(rendered.pdfPath),
    warnings: inspected.warnings,
    checks: {
      ooxml_crc: 'passed',
      slide_bounds: inspected.warnings.some((value) => value.includes('beyond the slide')) ? 'warning' : 'passed',
      text_fit: inspected.warnings.some((value) => value.includes('text overflow')) ? 'warning' : 'passed',
      text_overlap: inspected.warnings.some((value) => value.includes('text overlap')) ? 'warning' : 'passed',
      rendered_text: inspected.warnings.some((value) => value.includes('missing text')) ? 'warning' : 'passed',
      libreoffice_render: 'passed',
      rendered_page_count: 'passed',
    },
  };
  fs.writeFileSync(path.join(qaDir, 'presentation-qa.json'), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${report.status.toUpperCase()}: ${inspected.slideCount} slides rendered; ${inspected.warnings.length} warnings\n`);
  if (strict && inspected.warnings.length) process.exit(2);
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === 'version' || command === '--version') {
    process.stdout.write(`${VERSION}\n`);
    return;
  }
  if (command === 'guide') {
    process.stdout.write(`${GUIDE}\n`);
    return;
  }
  if (command === 'build') {
    if (args.length < 2) usage();
    const script = resolveInsideWorkspace(args[0], 'authoring script');
    const output = resolveInsideWorkspace(args[1], 'PPTX output');
    const options = parseOptions(args.slice(2));
    if (path.extname(script).toLowerCase() !== '.cjs' || path.extname(output).toLowerCase() !== '.pptx') {
      fail('build requires a .cjs source and .pptx output');
    }
    const author = require(script);
    if (typeof author !== 'function') fail('authoring module must export one async function');
    fs.mkdirSync(path.dirname(output), { recursive: true });
    await author({ pptxgen: require('pptxgenjs'), output });
    const qaDir = options.qaDir || path.join(path.dirname(output), `${path.basename(output, '.pptx')}-qa`);
    await verify(output, qaDir, options.strict);
    return;
  }
  if (command === 'verify') {
    if (args.length < 1) usage();
    const input = resolveInsideWorkspace(args[0], 'PPTX input');
    const options = parseOptions(args.slice(1));
    const qaDir = options.qaDir || path.join(path.dirname(input), `${path.basename(input, '.pptx')}-qa`);
    await verify(input, qaDir, options.strict);
    return;
  }
  usage();
}

main().catch((error) => fail(`presentation operation failed: ${error.message}`, 70));
