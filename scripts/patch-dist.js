#!/usr/bin/env node
/**
 * Patch the bundled dist/index.cjs to fix CommonJS compatibility issues
 * 1. Remove import.meta.resolve() ES module syntax
 * 2. Fix circular *_require reference patterns created by ncc bundler
 */

const fs = require('fs');
const path = require('path');

const distFile = path.join(__dirname, '..', 'dist', 'index.cjs');

console.log('Patching dist/index.cjs for CommonJS compatibility...');

let content = fs.readFileSync(distFile, 'utf8');
const originalLength = content.length;
let patchCount = 0;

// Patch 1: Replace import.meta.resolve() with error-throwing function
// This is safe because the code has a try-catch around it
const patch1Before = content.length;
content = content.replace(/import\.meta\.resolve\(/g, '(function(){throw new Error("import.meta not available in CommonJS")})(');
if (content.length !== patch1Before) {
  patchCount++;
  console.log(`  ✓ Patched import.meta.resolve() (${(patch1Before - content.length) / -1} chars added)`);
}

// Patch 2: Fix circular *_require reference patterns
// The ncc bundler sometimes creates patterns like: const esm_require = createRequire(esm_require("url")...)
// We need to replace the inner self-reference with plain require
const circularPatterns = [
  /lib_require\("url"\)/g,
  /esm_require\("url"\)/g,
  /lib_require\("path"\)/g,
  /esm_require\("path"\)/g,
  /lib_require\("fs"\)/g,
  /esm_require\("fs"\)/g,
];

let circularPatchCount = 0;
circularPatterns.forEach(pattern => {
  const beforePatch = content;
  content = content.replace(pattern, (match) => {
    const moduleName = match.match(/"([^"]+)"/)[1];
    return `require("${moduleName}")`;
  });
  if (content !== beforePatch) {
    circularPatchCount++;
  }
});

if (circularPatchCount > 0) {
  patchCount++;
  console.log(`  ✓ Fixed ${circularPatchCount} circular *_require reference(s)`);
}

if (content.length !== originalLength) {
  fs.writeFileSync(distFile, content, 'utf8');
  console.log(`✓ Successfully patched dist/index.cjs (${patchCount} patch types applied, ${originalLength - content.length} bytes changed)`);
} else {
  console.log('✓ No patches needed');
}
