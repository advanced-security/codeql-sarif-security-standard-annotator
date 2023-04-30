/* eslint-disable no-console */
import {resolve, dirname} from 'path'
import {env} from 'process'
import yargs from 'yargs'
import {hideBin} from 'yargs/helpers'
import {readFileSync, writeFileSync} from 'fs'
import * as core from '@actions/core'
import {DOMParser} from '@xmldom/xmldom'
import * as xpath from 'xpath'
import {JSONPath} from 'jsonpath-plus'

let sarifFilePath: string
let cweFilePath: string
let cweIdXpath: string
let securityStandardTag: string
let outputFilePath: string
let sarifResults: Object
let cweXml: Document

const defaultCweFilePath = resolve(dirname(process.argv[1]), '..//security-standards/owasp-top10-2021.xml')
const defaultCweFileXmlNs = {cwe: 'http://cwe.mitre.org/cwe-6'}
const defaulCweIdXpath = '/cwe:Weakness_Catalog/cwe:Weaknesses/cwe:Weakness/@ID'
const codeQlTagsJsonPath = '$.runs[*].tool.extensions[*].rules[*].properties.tags'
const codeQlCweTagPrefix = 'external/cwe/cwe-'
const defaultSecurityStandardTag = 'owasp-top10-2021'

// Parse Actions or CLI inputs
if (env.GITHUB_ACTIONS === 'true') {
  sarifFilePath = resolve(core.getInput('sarifFile'))
  cweFilePath = resolve(core.getInput('cweFile') || defaultCweFilePath)
  cweIdXpath = core.getInput('cweIdXpath') || defaulCweIdXpath
  securityStandardTag = core.getInput('securityStandardTag') || defaultSecurityStandardTag
  outputFilePath = resolve(core.getInput('outputFile') || sarifFilePath)
} else {
  const argv = yargs(hideBin(process.argv))
    .options({
      sarifFile: {type: 'string', demandOption: true},
      cweFile: {type: 'string'},
      cweIdXpath: {type: 'string'},
      securityStandardTag: {type: 'string'},
      outputFile: {type: 'string'}
    })
    .parseSync()
  sarifFilePath = resolve(argv.sarifFile)
  cweFilePath = resolve(argv.cweFile || defaultCweFilePath)
  cweIdXpath = argv.cweIdXpath || defaulCweIdXpath
  securityStandardTag = argv.securityStandardTag || defaultSecurityStandardTag
  outputFilePath = resolve(argv.outputFile || sarifFilePath)
}

console.log(`Using ${sarifFilePath} for SARIF file`)
console.log(`Using ${cweFilePath} for CWE file`)
console.log(`Using ${outputFilePath} for output file`)

// Load SARIF file
try {
  sarifResults = JSON.parse(readFileSync(sarifFilePath, 'utf8'))
} catch (err) {
  core.setFailed(`Unable to load SARIF file: ${err}`)
  process.exit(1)
}

// Load security standard CWE XML file
try {
  cweXml = new DOMParser().parseFromString(readFileSync(cweFilePath, 'utf8'))
} catch (err) {
  core.setFailed(`Unable to load CWE file: ${err}`)
  process.exit(1)
}
const select = xpath.useNamespaces(defaultCweFileXmlNs)
// Can't use instanceof Attr type to filter as Attr is not defined in the Node runtime and not exposed by xmldom
const cweIdAttributes = select(cweIdXpath, cweXml).filter((x): x is Attr => Object.getPrototypeOf(x).constructor.name === 'Attr')
const cweIdArray = cweIdAttributes.map(attribute => attribute.value)

// Add tag to SARIF file
JSONPath({
  path: codeQlTagsJsonPath,
  json: sarifResults,
  callback: tags => {
    for (const tag of tags) {
      if (tag.startsWith(codeQlCweTagPrefix)) {
        const cweId = tag.replace(codeQlCweTagPrefix, '')
        if (cweIdArray.includes(cweId)) {
          tags.push(securityStandardTag)
          return
        }
      }
    }
  }
})

// Output SARIF file with tag added
try {
  writeFileSync(outputFilePath, JSON.stringify(sarifResults))
} catch (err) {
  core.setFailed(`Unable to write SARIF file: ${err}`)
  process.exit(1)
}
