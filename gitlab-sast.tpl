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
    "start_time": "{{ now | date "2006-01-02T15:04:05" }}",
    "status": "success",
    "type": "sast"
  },
  "vulnerabilities": [
    {{- $first := true }}
    {{- range .Results }}
      {{- if eq .Class "sast" }}
        {{- range .Sast }}
          {{- if not $first }}
          ,
          {{- end }}
          {{- $first = false }}
          {
            "id": "{{ .CheckID }}",
            "category": "{{ .Category }}",
            "name": {{ .Title | printf "%q" }},
            "message": {{ .Message | printf "%q" }},
            "description": {{ .Message | printf "%q" }},
            "severity": {{ .Severity | printf "%q" | lower }},
            "confidence": {{ .Confidence | printf "%q" | lower }},
            "solution": {{ if .Fix }}{{ .Fix | printf "%q" }}{{ else if .Remediation }}{{ .Remediation | printf "%q" }}{{ else }}"No solution provided"{{ end }},
            "location": {
              "file": {{ $.Target | printf "%q" }},
              "start_line": {{ .StartLine }},
              "end_line": {{ .EndLine }}
            },
            "identifiers": [
              {
                "type": "cwe",
                "name": "{{ .CWE }}",
                "value": "{{ .CWE }}",
                "url": "https://cwe.mitre.org/data/definitions/{{ index (split .CWE ":") 0 }}.html"
              }
            ],
            "scanner": {
              "id": "trivy",
              "name": "Trivy"
            },
            "links": [
              {{- $linkFirst := true }}
              {{- range .References }}
                {{- if not $linkFirst }}
                ,
                {{- end }}
                {{- $linkFirst = false }}
                {
                  "url": {{ . | printf "%q" }}
                }
              {{- end }}
            ]
          }
        {{- end }}
      {{- end }}
    {{- end }}
  ]
}
