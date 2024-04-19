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
let outputFilePath: string
let sarifResults: Object
let cweXml: Document

let cweFilePath = resolve(dirname(process.argv[1]), '..//security-standards/owasp-top10-2021.xml')
let cweFileXmlNs = {cwe: 'http://cwe.mitre.org/cwe-6'}
let cweIdXpath = '/cwe:Weakness_Catalog/cwe:Weaknesses/cwe:Weakness/@ID'
let categoryXpath = '/cwe:Weakness_Catalog/cwe:Categories/cwe:Category[contains(@Name, "OWASP Top Ten 2021")]'
let categoryMembersXpath = 'cwe:Relationships/cwe:Has_Member/@CWE_ID'
let categoryNameAttr = '@Name'
let categoryNameReplaceSearch = 'OWASP Top Ten 2021 Category '
let codeQlCweTagPrefix = 'external/cwe/cwe-'
let securityStandardTag = 'owasp-top10-2021'
let codeQlTagsJsonPath = '$.runs[*].tool.extensions[*].rules[*].properties.tags'

// Parse Actions or CLI inputs
if (env.GITHUB_ACTIONS === 'true') {
  sarifFilePath = resolve(core.getInput('sarifFile'))
  cweFilePath = resolve(core.getInput('cweFile') || cweFilePath)
  cweIdXpath = core.getInput('cweIdXpath') || cweIdXpath
  categoryXpath = core.getInput('cweCategoryXpath') || categoryXpath
  securityStandardTag = core.getInput('securityStandardTag') || securityStandardTag
  outputFilePath = resolve(core.getInput('outputFile') || sarifFilePath)
} else {
  const argv = yargs(hideBin(process.argv))
    .options({
      sarifFile: {type: 'string', demandOption: true},
      cweFile: {type: 'string', default: cweFilePath},
      cweIdXpath: {type: 'string', default: cweIdXpath},
      cweCategoryXpath: {type: 'string', default: categoryXpath},
      securityStandardTag: {type: 'string', default: securityStandardTag},
      outputFile: {type: 'string'}
    })
    .parseSync()
  sarifFilePath = resolve(argv.sarifFile)
  cweFilePath = resolve(argv.cweFile)
  cweIdXpath = argv.cweIdXpath
  categoryXpath = argv.cweCategoryXpath
  securityStandardTag = argv.securityStandardTag
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
  console.log(`Unable to load CWE file: ${err}`)
  core.setFailed(`Unable to load CWE file: ${err}`)
  process.exit(1)
}
const select = xpath.useNamespaces(cweFileXmlNs)
const cweIds = (select(cweIdXpath, cweXml) as Attr[]).map(attribute => attribute.value)
const cweCategoryNodes = (select(categoryXpath, cweXml) as Node[])
let cweCategories: {[k: string]: string[]} = {}
for (const cweCategoryNode of cweCategoryNodes) {
  let memberCweIds = (select(categoryMembersXpath, cweCategoryNode) as Attr[]).map(attr => attr.value)
  let categoryName = (select(categoryNameAttr, cweCategoryNode, true) as Attr).value.replace(categoryNameReplaceSearch, '')
  for (const cweId of memberCweIds) {
    cweCategories[cweId] = [...(cweCategories[cweId] || []), categoryName]
  }
}

// Add tag to SARIF file
JSONPath({
  path: codeQlTagsJsonPath,
  json: sarifResults,
  callback: (tags: string[]) => {
    for (const tag of tags) {
      if (tag.startsWith(codeQlCweTagPrefix)) {
        const cweId = tag.replace(codeQlCweTagPrefix, '')
        if (cweIds.includes(cweId)) {
          tags.push(securityStandardTag)
          tags.push(...cweCategories[cweId])
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
