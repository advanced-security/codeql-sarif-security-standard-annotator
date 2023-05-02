## CodeQL SARIF Security Standard Annotator

Compare a CodeQL SARIF results file to a security standard CWE list and annotate the SARIF rules with a tag to highlight results applicable to the security standard

- Defaults to a comparison against the OWASP Top 10 2021 CWE mapping taken from https://cwe.mitre.org/data/xml/views/1344.xml.zip
- Any XML file can be provided as an alternative, with the option to provide an XPath query that identifies the CWE ID values to use in the conparison
- Tag value is configurable

## Usage in GitHub Actions

```
- name: Perform CodeQL Analysis
  uses: github/codeql-action/analyze@v2
  with:
    upload: false
    output: sarif-results

- name: Annotate CodeQL SARIF with OWASP Top 10 2021 tag
  uses: advanced-security/codeql-sarif-security-standard-annotator@v1
  with:
    sarifFile: sarif-results/${{matrix.language}}.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: sarif-results/${{matrix.language}}.sarif
```

```
inputs:
  sarifFile:
    required: true
    description: 'The CodeQL SARIF result file'
  cweFile:
    required: false
    description: 'The CWE list XML file, defaults to OWASP Top 10 2021'
  cweIdXpath:
    required: false
    description: 'The XPath query that selects CWE ID numbers from the CWE list file'
  securityStandardTag:
    required: false
    description: 'The security standard tag to add to the SARIF file, defaults to "owasp-top10-2021"'
  outputFile:
    required: false
    description: 'The output SARIF file path, defaults to the input SARIF file path'
```

## Dev requirements

The repo include a Node.js devcontainer [configuration](.devcontainer/devcontainer.json) which should be used for development. See [CONTRIBUTING](CONTRIBUTING.md).

## License 

This project is licensed under the terms of the MIT open source license. Please refer to [MIT](./LICENSE.txt) for the full terms.

## Maintainers 

See [CODEOWNERS](CODEOWNERS)

## Support

See [SUPPORT](SUPPORT.md)

## Acknowledgement

@aegilops for the inspiration
