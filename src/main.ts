import {resolve, dirname} from 'path'
import {env} from 'process'
import yargs from 'yargs'
import {hideBin} from 'yargs/helpers'
import {readFileSync, writeFileSync} from 'fs'
import * as core from '@actions/core'
import {DOMParser} from '@xmldom/xmldom'
import * as xpath from 'xpath'
import {JSONPath} from 'jsonpath-plus'
import {LogLevel, log} from './utils'

let sarifFilePath: string
let outputFilePath: string
let sarifResults: object
let cweXml: Document

let cweFilePath = resolve(dirname(process.argv[1]), '..//security-standards/owasp-top10-2021.xml')
const cweFileXmlNs = {cwe: 'http://cwe.mitre.org/cwe-6'}
let cweIdXpath = '/cwe:Weakness_Catalog/cwe:Weaknesses/cwe:Weakness/@ID'
let categoryXpath = '/cwe:Weakness_Catalog/cwe:Categories/cwe:Category[contains(@Name, "OWASP Top Ten 2021")]'
const categoryMembersXpath = 'cwe:Relationships/cwe:Has_Member/@CWE_ID'
const categoryNameAttr = '@Name'
const categoryNameReplaceSearch = 'OWASP Top Ten 2021 Category '
const codeQlCweTagPrefix = 'external/cwe/cwe-'
let securityStandardTag = 'owasp-top10-2021'
const codeQlTagsJsonPath = '$.runs[*].tool.extensions[*].rules[*].properties.tags'

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

log(`Using ${sarifFilePath} for SARIF file`)
log(`Using ${cweFilePath} for CWE file`)
log(`Using ${outputFilePath} for output file`)

// Load SARIF file
try {
  sarifResults = JSON.parse(readFileSync(sarifFilePath, 'utf8'))
} catch (err) {
  log(`Unable to load SARIF file`, LogLevel.Error)
  core.setFailed(err as Error)
  throw err
}

// Load security standard CWE XML file
try {
  cweXml = new DOMParser().parseFromString(readFileSync(cweFilePath, 'utf8'))
} catch (err) {
  log(`Unable to load CWE file`, LogLevel.Error)
  core.setFailed(err as Error)
  throw err
}
const select = xpath.useNamespaces(cweFileXmlNs)
const cweIds = (select(cweIdXpath, cweXml) as Attr[]).map(attribute => attribute.value)
const cweCategoryNodes = select(categoryXpath, cweXml) as Node[]
const cweCategories: {[k: string]: string[]} = {}
for (const cweCategoryNode of cweCategoryNodes) {
  const memberCweIds = (select(categoryMembersXpath, cweCategoryNode) as Attr[]).map(attr => attr.value)
  const categoryName = (select(categoryNameAttr, cweCategoryNode, true) as Attr).value.replace(categoryNameReplaceSearch, '')
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
  log(`Unable to write SARIF file`, LogLevel.Error)
  core.setFailed(err as Error)
  throw err
}
