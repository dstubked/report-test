{
  "version": "{{ appVersion }}",
  "scan": {
    "analyzer": {
      "id": "trivy",
      "name": "Trivy",
      "vendor": {
        "name": "Aqua Security"
      },
      "version": "{{ appVersion }}"
    },
    "end_time": "{{ now | date \"2006-01-02T15:04:05\" }}",
    "scanner": {
      "id": "trivy",
      "name": "Trivy",
      "url": "https://github.com/aquasecurity/trivy/",
      "vendor": {
        "name": "Aqua Security"
      },
      "version": "{{ appVersion }}"
    },
    "start_time": "{{ now | date \"2006-01-02T15:04:05\" }}",
    "status": "success",
    "type": "sast"
  },
  "vulnerabilities": [
    {{- $first := true }}
    {{- range .Results }}  // Iterate over each result
      {{- if .Sast }}  // Check if there are SAST findings
        {{- range .Sast }}  // Iterate over SAST findings within each result
          {{ if not $first }}{{ "," }}{{ end }}
          {
            "id": "{{ .CheckID }}",
            "category": "{{ .Category }}",  // Assuming Category is part of SAST findings
            "name": {{ .Title | printf "%q" }},
            "message": {{ .Message | printf "%q" }},
            "description": {{ .Message | printf "%q" }},
            "severity": {{ .Severity | printf "%q" | lower }},
            "confidence": {{ .Confidence | printf "%q" | lower }},
            "solution": {{ if .Fix }}{{ .Fix | printf "%q" }}{{ else if .Remediation }}{{ .Remediation | printf "%q" }}{{ else }}"No solution provided"{{ end }},
            "location": {
              "file": "{{ $.Target }}",  // Using Target from the outer context
              "start_line": {{ .StartLine }},
              "end_line": {{ .EndLine }}
            },
            "identifiers": [
              {{- range .CWE }}
                {
                  "type": "cwe",
                  "name": "{{ . }}",
                  "value": "{{ . }}",
                  "url": "https://cwe.mitre.org/data/definitions/{{ . }}.html"
                }{{ if not (eq (add (index $.CWE) 1) (len $.CWE)) }},{{ end }}
              {{- end }}
            ],
            "scanner": {
              "id": "trivy",
              "name": "Trivy"
            },
            "links": [
              {{- range .References }}
                {
                  "url": {{ . | printf "%q" }}
                }{{ if not (eq (add (index $.References) 1) (len $.References)) }},{{ end }}
              {{- end }}
            ]
          }
          {{ $first = false }}  // Set first to false after first iteration
        {{- end }}
      {{- end }}
    {{- end }}
  ]
}
