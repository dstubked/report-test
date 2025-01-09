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
    {{- $t_first := true }}
    {{- range . }}
      {{- $target := .Target }}  // Accessing Target from each result
      {{- range .Sast }}  // Accessing SAST findings within each result
        {{- if $t_first }}
          {{- $t_first = false }}
        {{- else -}}
          ,
        {{- end }}
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
            "file": {{ $target | printf "%q" }},  // Using Target here
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
              }{{ if not @last }},{{ end }}
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
              }{{ if not @last }},{{ end }}
            {{- end }}
          ]
        }
      {{- end }}
    {{- end }}
  ]
}
