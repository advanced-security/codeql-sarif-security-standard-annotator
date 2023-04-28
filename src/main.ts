import yargs from 'yargs'
import {hideBin} from 'yargs/helpers'
import {readFileSync, writeFileSync} from 'fs'
import * as core from '@actions/core'
import {DOMParser} from '@xmldom/xmldom'
import * as xpath from 'xpath'
import type {Log} from 'sarif'

// Global variables
let sarifResults: Log
let cweXml: Document
const codeQlCweTagPrefix = 'external/cwe/cwe-'
const xmlNs = {cwe: 'http://cwe.mitre.org/cwe-6'}
const cweIdXpath = '/cwe:Weakness_Catalog/cwe:Weaknesses/cwe:Weakness/@ID'

// Parse arguments
const argv = yargs(hideBin(process.argv))
  .options({
    sarifFile: {type: 'string', demandOption: true},
    cweFile: {type: 'string', demandOption: true},
    securityStandardTag: {type: 'string', demandOption: true},
    outputFile: {type: 'string', demandOption: true}
  })
  .parseSync()

// Load SARIF file
try {
  sarifResults = JSON.parse(readFileSync(argv.sarifFile, 'utf8'))
} catch (err) {
  core.setFailed(`Unable to load SARIF file: ${err}`)
  process.exit(1)
}

// Load security standard CWE XML file
try {
  cweXml = new DOMParser().parseFromString(readFileSync(argv.cweFile, 'utf8'))
} catch (err) {
  core.setFailed(`Unable to load CWE file: ${err}`)
  process.exit(1)
}
const select = xpath.useNamespaces(xmlNs)
const cweIdAttributes = select(cweIdXpath, cweXml).filter((x): x is Attr => Object.getPrototypeOf(x).constructor.name === 'Attr')
const cweIdArray = cweIdAttributes.map(attribute => attribute.value)

// Add tag to SARIF file
for (const run of sarifResults.runs) {
  for (const extension of run.tool.extensions || []) {
    for (const rule of extension.rules || []) {
      for (const tag of rule.properties?.tags || []) {
        if (tag.startsWith(codeQlCweTagPrefix)) {
          const cweId = tag.replace(codeQlCweTagPrefix, '')
          if (cweIdArray.includes(cweId)) {
            rule.properties?.tags?.push(argv.securityStandardTag)
            break
          }
        }
      }
    }
  }
}

// Output SARIF file with tag added
try {
  writeFileSync(argv.outputFile, JSON.stringify(sarifResults))
} catch (err) {
  core.setFailed(`Unable to write SARIF file: ${err}`)
  process.exit(1)
}
