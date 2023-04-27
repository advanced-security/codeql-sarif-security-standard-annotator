import yargs from 'yargs'
import {hideBin} from 'yargs/helpers'
import * as fs from 'fs'
import * as core from '@actions/core'
import {parseXml, XmlElement} from '@rgrove/parse-xml'

function isXmlElement(xmlThing: any): xmlThing is XmlElement {
  return xmlThing instanceof XmlElement
}

// parse arguments
const argv = yargs(hideBin(process.argv))
  .options({
    sarifFile: {type: 'string', demandOption: true},
    cweFile: {type: 'string', demandOption: true}
  })
  .parseSync()

// load SARIF file
try {
  var sarifResults = JSON.parse(fs.readFileSync(argv.sarifFile, 'utf8'))
} catch (err) {
  core.setFailed(`Unable to load SARIF file: ${err}`)
  process.exit(1)
}

// load security standard CWE list
try {
  var cweList = parseXml(fs.readFileSync(argv.cweFile, 'utf8'))
} catch (err) {
  core.setFailed(`Unable to load CWE list: ${err}`)
  process.exit(1)
}

var cweIDList: number[] = []

cweList.children.filter(isXmlElement).forEach(child => {
  if (child.name === 'Weakness_Catalog') {
    child.children.filter(isXmlElement).forEach(child => {
      if (child.name === 'Weaknesses') {
        child.children.filter(isXmlElement).forEach(weakness => {
          cweIDList.push(parseInt(weakness.attributes.ID))
        })
      }
    })
  }
})

cweIDList.sort()

// Annotate SARIF file
sarifResults.runs.forEach((run: any) => {
  run.tool.extensions?.forEach((extension: any) => {
    extension.rules?.forEach((rule: any) => {
      rule.properties?.tags?.forEach((tag: string) => {
        if (tag.startsWith('external/cwe/cwe-')) {
          const cweId = tag.split('-').pop()
          if (cweId !== undefined && cweIDList.includes(parseInt(cweId))) {
            rule.properties.tags.push('owasp-2021')
          }
        }
      })
    })
  })
})

// Output report
try {
  fs.writeFileSync(argv.sarifFile, JSON.stringify(sarifResults))
} catch (err) {
  core.setFailed(`Unable to write SARIF file: ${err}`)
  process.exit(1)
}
