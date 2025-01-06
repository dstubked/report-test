{
  "version": "15.0.7",
  "scan": {
    "analyzer": {
      "id": "trivy",
      "name": "Trivy",
      "vendor": {
        "name": "Aqua Security"
      },
      "version": "{{ appVersion }}"
    },
    "end_time": "{{ now | date "2006-01-02T15:04:05" }}",
    "scanner": {
      "id": "trivy",
      "name": "Trivy",
      "url": "https://github.com/aquasecurity/trivy/",
      "vendor": {
        "name": "Aqua Security"
      },
      "version": "{{ appVersion }}"
    },
    "start_time": "{{ now | date '2006-01-02T15:04:05' }}",
    "status": "success",
    "type": "sast"
  },
  "vulnerabilities": [
    {{- $t_first := true }}
    {{- range . }}  // Iterate over Results
      {{- $target := .Target }}  // Access Target from the current result
      {{- range .Sast -}}  // Now iterate over SAST findings within this result
        {{- if $t_first -}}
          {{- $t_first = false -}}
        {{ else -}}
          ,
        {{- end }}
        {
          "id": "{{ .CheckID }}",  // Unique identifier for the check
          "name": {{ .Title | printf "%q" }},  // Title of the finding
          "description": {{ .Message | printf "%q" }},  // Description of the finding
          "severity": "{{ .Severity }}",  // Severity level
          "solution": {{ if .Remediation }}{{ .Remediation | printf "%q" }}{{ else }}"No solution provided"{{ end }},  // Suggested fix
          "location": {
            "file": "{{ $target }}",  // Path to the file where the issue was found
            "start_line": {{ .StartLine }},  // Start line of the issue
            "end_line": {{ .EndLine }}  // End line of the issue
          },
          "cwe": [
            {{- range .CWE }}
              "{{ . }}"
              {{- if not @last }},{{ end }}  // Add comma if not last element
            {{- end }}
          ],
          "owasp_top_10": [
            {{- range .OWASP }}
              "{{ . }}"
              {{- if not @last }},{{ end }}  // Add comma if not last element
            {{- end }}
          ],
          // Additional fields as necessary
          "confidence": "{{ .Confidence }}",  // Confidence level of the finding
          "likelihood": "{{ .Likelihood }}",  // Likelihood of occurrence
          "impact": "{{ .Impact }}",  // Impact description
          "references": [
            {{- range .References }}
              "{{ . }}"
              {{- if not @last }},{{ end }}  // Add comma if not last element
            {{- end }}
          ]
        }
      {{- end }}
    {{- end }}
  ],
  "remediations": []
}
