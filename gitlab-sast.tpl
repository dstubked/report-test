{
  "version": "15.0.7",
  "vulnerabilities": [
    {{- $first := true }}
    {{- range . }}
      {{- if eq .Class "sast" }}
        {{- range .Sast }}
          {{- if not $first }}
          ,
          {{- end }}
          {{- $first = false }}
          {
            "id": "{{ .CheckID }}",
            "category": "sast",
            "name": {{ .Title | printf "%q" }},
            "message": {{ .Message | printf "%q" }},
            "description": {{ .Message | printf "%q" }},
            "severity": {{ .Severity | printf "%q" }},
            "confidence": {{ .Confidence | printf "%q" }},
            "solution": {{ if .Remediation }}{{ .Remediation | printf "%q" }}{{ else }}"No solution provided"{{ end }},
            "scanner": {
              "id": "trivy",
              "name": "Trivy"
            },
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
  ],
  "scan": {
    "scanner": {
      "id": "trivy",
      "name": "Trivy",
      "url": "https://github.com/aquasecurity/trivy/",
      "vendor": {
        "name": "Aqua Security"
      },
      "version": "{{ appVersion }}"
    },
    "type": "sast",
    "start_time": "{{ now | date "2006-01-02T15:04:05" }}",
    "end_time": "{{ now | date "2006-01-02T15:04:05" }}",
    "status": "success"
  }
}
