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
    "start_time": "{{ now | date "2006-01-02T15:04:05" }}",
    "status": "success",
    "type": "sast"
  },
  "vulnerabilities": [
    {{- $t_first := true }}
    {{- range .Results }}
      {{- $target := .Target }}
      {{- range .Sast }}
        {{- if $t_first }}
          {{- $t_first = false }}
        {{- else -}}
          ,
        {{- end }}
        {
          "id": "{{ .CheckID }}",
          "category": "sast",
          "name": {{ .Title | printf "%q" }},
          "message": {{ .Message | printf "%q" }},
          "description": {{ .Message | printf "%q" }},
          "severity": {{ .Severity | printf "%q" | lower }},
          "confidence": {{ .Confidence | printf "%q" | lower }},
          "solution": {{ if .Fix }}{{ .Fix | printf "%q" }}{{ else if .Remediation }}{{ .Remediation | printf "%q" }}{{ else }}"No solution provided"{{ end }},
          "location": {
            "file": {{ $target | printf "%q" }},
            "start_line": {{ .StartLine }},
            "end_line": {{ .EndLine }}
          },
          "identifiers": [
            {{- $cwe_first := true }}
            {{- range .CWE }}
              {{- if $cwe_first }}
                {{- $cwe_first = false }}
              {{- else -}}
                ,
              {{- end }}
              {
                "type": "cwe",
                "name": "CWE-{{ . }}",
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
              {{- if $ref_first }}
                {{- $ref_first = false }}
              {{- else -}}
                ,
              {{- end }}
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
