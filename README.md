## CodeQL SARIF Security Standard Annotator

Compare a CodeQL SARIF results file to a security standard CWE list and annotate the SARIF rules with a tag to highlight results applicable to the security standard

- Defaults to a comparison against the OWASP Top 10 2021 CWE mapping taken from https://cwe.mitre.org/data/xml/views/1344.xml.zip
- Any XML file can be provided as an alternative, with the option to provide an XPath query that identifies the CWE ID values to use in the comparison
- Tag value is configurable

This supports the ability to filter the Security dashboards by `tag`
<img width="783" alt="filter the Security dashboards by tag" src="https://github.com/advanced-security/codeql-sarif-security-standard-annotator/assets/1760475/ca1b5519-2a9c-4f03-8dca-4f03bc6fbc05">
<br/><br/>
As well as displaying this information along side the Code scanning alert
<img width="614" alt="displaying this information along side the Code scanning alert" src="https://github.com/advanced-security/codeql-sarif-security-standard-annotator/assets/1760475/30b1c71a-8ee0-4c49-acbf-2161df7c7582">

## Usage in GitHub Actions

```
- name: Perform CodeQL Analysis
  uses: github/codeql-action/analyze@v3
  with:
    upload: false
    output: sarif-results

- name: Find SARIF file
  id: find_sarif
  run: echo "SARIF_FILE=$(find $PWD/sarif-results -name '*.sarif' | head -n 1)" >> $GITHUB_ENV

- name: Annotate CodeQL SARIF with OWASP Top 10 2021 tag
  uses: advanced-security/codeql-sarif-security-standard-annotator@main
  with:
    sarifFile: ${{ env.SARIF_FILE }}

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sarif-results
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
