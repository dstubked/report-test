{
  "version": "15.0.7",
  "scan": {
    "analyzer": {
      "id": "trivy",
      "name": "Trivy",
      "vendor": {
        "name": "Aqua Security"
      },
      "version": "{{ .Version }}"
    },
    "end_time": "{{ now | date "2006-01-02T15:04:05" }}",
    "scanner": {
      "id": "trivy",
      "name": "Trivy",
      "url": "https://github.com/aquasecurity/trivy/",
      "vendor": {
        "name": "Aqua Security"
      },
      "version": "{{ .Version }}"
    },
    "start_time": "{{ now | date "2006-01-02T15:04:05" }}",
    "status": "success",
    "type": "sast"
  },
  "vulnerabilities": [
    {{- $t_first := true }}
    {{- range . }}
      {{- $target := .Target }}
      {{- range .Sast }}
        {{- if $t_first }}
          {{- $t_first = false }}
        {{- else }}
          ,
        {{- end }}
        {
          "id": "{{ .CheckID }}",
          "name": {{ .Title | printf "%q" }},
          "description": {{ .Message | printf "%q" }},
          "severity": "{{ .Severity }}",
          "solution": {{ if .Remediation }}{{ .Remediation | printf "%q" }}{{ else }}"No solution provided"{{ end }},
          "location": {
            "file": "{{ $target }}",
            "start_line": {{ .StartLine }},
            "end_line": {{ .EndLine }}
          },
          "cwe": [
            {{- $cwe_first := true }}
            {{- range .CWE }}
              {{- if $cwe_first }}
                {{- $cwe_first = false }}
              {{- else }}
                ,
              {{- end }}
              "{{ . }}"
            {{- end }}
          ],
          "owasp_top_10": [
            {{- $owasp_first := true }}
            {{- range .OWASP }}
              {{- if $owasp_first }}
                {{- $owasp_first = false }}
              {{- else }}
                ,
              {{- end }}
              "{{ . }}"
            {{- end }}
          ],
          "confidence": "{{ .Confidence }}",
          "likelihood": "{{ .Likelihood }}",
          "impact": "{{ .Impact }}",
          "references": [
            {{- $ref_first := true }}
            {{- range .References }}
              {{- if $ref_first }}
                {{- $ref_first = false }}
              {{- else }}
                ,
              {{- end }}
              "{{ . }}"
            {{- end }}
          ]
        }
      {{- end }}
    {{- end }}
  ],
  "remediations": []
}
