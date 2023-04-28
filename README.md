# codeql-sarif-security-standard-annotator

Compare a CodeQL SARIF results file to a security standard CWE list and annotate the SARIF rules with a tag to highlight results applicable to the security standard

## Usage in GitHub Actions

```
- name: Annotate CodeQL SARIF with OWASP Top 10 2021 tag
  uses: ctcampbell/codeql-sarif-security-standard-annotator@v1
```

```
inputs:
  sarifFile:
    required: true
    description: 'The CodeQL SARIF result file'
  cweFile:
    required: false
    description: 'The CWE list XML file'
    default: '${{ github.action_path }}/security-standards/owasp-top10-2021.xml'
  securityStandardTag:
    required: false
    description: 'The security standard tag to add to the SARIF file'
    default: 'owasp-top10-2021'
  outputFile:
    required: false
    description: 'The output SARIF file path, defaults to the input SARIF file path'
    default: '${{ inputs.sarifFile }}'
```