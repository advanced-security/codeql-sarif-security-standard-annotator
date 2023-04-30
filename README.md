# codeql-sarif-security-standard-annotator

Compare a CodeQL SARIF results file to a security standard CWE list and annotate the SARIF rules with a tag to highlight results applicable to the security standard

## Usage in GitHub Actions

```
- name: Perform CodeQL Analysis
  uses: github/codeql-action/analyze@v2
  with:
    category: "/language:${{matrix.language}}"
    upload: false
    output: sarif-results

- name: Annotate CodeQL SARIF with OWASP Top 10 2021 tag
  uses: ctcampbell/codeql-sarif-security-standard-annotator@v1
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
    description: 'The security standard tag to add to the SARIF file'
    default: 'owasp-top10-2021'
  outputFile:
    required: false
    description: 'The output SARIF file path, defaults to the input SARIF file path'
```
