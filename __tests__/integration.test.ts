import { readFileSync, unlinkSync } from 'fs';
import { resolve } from 'path';
import { execSync } from 'child_process';
import { describe, it, expect } from '@jest/globals';

describe('Integration Test', () => {
  const inputSarifPath = resolve(__dirname, '../test-data/webgoat.sarif');
  const expectedSarifPath = resolve(__dirname, '../test-data/webgoat-with-security-standard-tag.sarif.expected');
  const outputSarifPath = resolve(__dirname, '../test-data/webgoat-with-security-standard-tag.sarif');

  it('should annotate the SARIF file with the security standard tag', () => {
    // Run the main function using the compiled JavaScript version
    execSync(`node dist/index.js --sarifFile ${inputSarifPath} --outputFile ${outputSarifPath}`);

    // Read the output SARIF file
    const outputSarif = readFileSync(outputSarifPath, 'utf8');
    const expectedSarif = readFileSync(expectedSarifPath, 'utf8');

    // Compare the output with the expected SARIF file
    expect(JSON.parse(outputSarif)).toEqual(JSON.parse(expectedSarif));

    // Clean up the output file
    unlinkSync(outputSarifPath);
  });
});