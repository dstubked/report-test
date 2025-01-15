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
    {{- range . }}
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
            "file": "{{ $.Target }}",
            "start_line": {{ .StartLine }},
            "end_line": {{ .EndLine }}
          },
          "identifiers": [
            {{- $cwe_first := true }}
            {{- range .CWE }}
              {{- if not $cwe_first }},{{ end }}
              {{- $cwe_first = false }}
              {
                "type": "cwe",
                "name": "{{ . }}",
                "value": "{{ . }}",
                "url": "https://cwe.mitre.org/data/definitions/{{ . }}.html"
              }
            {{- end }}
          ],
          "scanner": {
            "id": "trivy",
            "name": "Trivy"
          },
          "links": [
            {{- $ref_first := true }}
            {{- range .References }}
              {{- if not $ref_first }},{{ end }}
              {{- $ref_first = false }}
              {
                "url": {{ . | printf "%q" }}
              }
            {{- end }}
          ]
        }
      {{- end }}
    {{- end }}
  ]
}
