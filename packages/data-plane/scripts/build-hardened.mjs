import * as esbuild from 'esbuild';
import JavaScriptObfuscator from 'javascript-obfuscator';
import fs from 'node:fs';
import path from 'node:path';

const distDir = path.join(process.cwd(), 'dist-hardened');
fs.mkdirSync(distDir, { recursive: true });

console.log('1/3 ⚡ Bundling & Tree-Shaking Data Plane into single artifact...');
const bundlePath = path.join(distDir, 'bundle.cjs');

await esbuild.build({
  entryPoints: ['src/index.ts'],
  bundle: true,
  platform: 'node',
  target: 'node24',
  format: 'cjs',
  minify: true,
  sourcemap: false,
  legalComments: 'none',
  external: ['node:sqlite', 'node:crypto', 'node:path', 'node:fs', 'node:os'],
  outfile: bundlePath,
});

console.log('2/3 🛡️ Applying AST Control-Flow Flattening & String Array Encryption...');
const rawBundleCode = fs.readFileSync(bundlePath, 'utf8');

const obfuscatedResult = JavaScriptObfuscator.obfuscate(rawBundleCode, {
  compact: true,
  controlFlowFlattening: true,
  controlFlowFlatteningThreshold: 0.5,
  deadCodeInjection: true,
  deadCodeInjectionThreshold: 0.2,
  identifierNamesGenerator: 'hexadecimal',
  renameGlobals: false,
  selfDefending: true,
  splitStrings: true,
  splitStringsChunkLength: 8,
  stringArray: true,
  stringArrayCallsTransform: true,
  stringArrayEncoding: ['rc4'],
  stringArrayThreshold: 0.75,
  target: 'node',
  transformObjectKeys: true,
  unicodeEscapeSequence: false,
});

const hardenedPath = path.join(distDir, 'aindigo-engine.cjs');
fs.writeFileSync(hardenedPath, obfuscatedResult.getObfuscatedCode(), 'utf8');
fs.unlinkSync(bundlePath); // Remove un-obfuscated intermediate bundle

console.log('3/3 📦 Generating Node.js v24 SEA (Single Executable Application) V8 Snapshot Config...');
const seaConfig = {
  main: 'dist-hardened/aindigo-engine.cjs',
  output: 'dist-hardened/sea-prep.blob',
  disableExperimentalSEAWarning: true,
  useSnapshot: false,
  useCodeCache: true, // Compiles into V8 bytecode cache inside the binary
};

fs.writeFileSync(
  path.join(process.cwd(), 'sea-config.json'),
  JSON.stringify(seaConfig, null, 2),
  'utf8'
);

console.log('✅ Hardened build complete: dist-hardened/aindigo-engine.cjs');
