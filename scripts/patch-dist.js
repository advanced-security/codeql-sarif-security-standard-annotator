#!/usr/bin/env node
/**
 * Patch the bundled dist/index.cjs to remove ES module syntax that causes issues in CommonJS
 * Specifically, replace import.meta.resolve() with a fallback that works in CommonJS
 */

const fs = require('fs');
const path = require('path');

const distFile = path.join(__dirname, '..', 'dist', 'index.cjs');

console.log('Patching dist/index.cjs to remove import.meta.resolve()...');

let content = fs.readFileSync(distFile, 'utf8');

// Replace import.meta.resolve() with null (which will be caught by the try-catch)
// This is safe because the code has a try-catch around it
const before = content.length;
content = content.replace(/import\.meta\.resolve\(/g, '(function(){throw new Error("import.meta not available in CommonJS")})(');
const after = content.length;

if (before !== after) {
  fs.writeFileSync(distFile, content, 'utf8');
  console.log(`✓ Patched dist/index.cjs (replaced ${(before - after) / -1} characters)`);
} else {
  console.log('✓ No import.meta.resolve() found to patch');
}
