{{- define "nexus.fullname" -}}
{{- if contains .Chart.Name .Release.Name }}{{ .Release.Name | trunc 50 | trimSuffix "-" }}{{ else }}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 50 | trimSuffix "-" }}{{ end }}
{{- end }}

{{- define "nexus.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end }}

{{/* Selector labels for one component: include "nexus.selector" (list . "api") */}}
{{- define "nexus.selector" -}}
{{- $ := index . 0 -}}
app.kubernetes.io/name: {{ $.Chart.Name }}
app.kubernetes.io/instance: {{ $.Release.Name }}
app.kubernetes.io/component: {{ index . 1 }}
{{- end }}

{{- define "nexus.secretName" -}}
{{- .Values.secret.existingSecret | default (printf "%s-secrets" (include "nexus.fullname" .)) }}
{{- end }}

{{- define "nexus.image" -}}
{{- $img := index . 0 -}}{{- $ := index . 1 -}}
{{ $img.repository }}:{{ $img.tag | default $.Chart.AppVersion }}
{{- end }}

{{- define "nexus.required" -}}
{{- $_ := required "publicUrl is required (https://…)" .Values.publicUrl -}}
{{- $_ := required "apiPublicUrl is required (https://…)" .Values.apiPublicUrl -}}
{{- if and (not .Values.secret.existingSecret) (not .Values.secret.values) -}}
{{- fail "set secret.existingSecret, or secret.values (see values.yaml)" -}}
{{- end -}}
{{- end }}

{{/* Environment shared by the API, the worker and the migration job (secret references, never values). */}}
{{- define "nexus.env" -}}
- { name: NEXUS_ENV, value: prod }
- { name: NEXUS_PUBLIC_URL, value: {{ .Values.publicUrl | quote }} }
- { name: NEXUS_API_PUBLIC_URL, value: {{ .Values.apiPublicUrl | quote }} }
- { name: NEXUS_TRUST_PROXY, value: "true" }
- { name: NEXUS_MAIL_FROM, value: {{ .Values.config.mailFrom | quote }} }
- { name: NEXUS_SIGNUP, value: {{ .Values.config.signup | quote }} }
- { name: NEXUS_ALLOW_PRIVATE_DIRECTORY, value: {{ .Values.config.allowPrivateDirectory | toString | quote }} }
- { name: NEXUS_LOG_FORMAT, value: {{ .Values.config.logFormat | quote }} }
- { name: NEXUS_DB_POOL_SIZE, value: {{ .Values.config.dbPoolSize | toString | quote }} }
{{- with .Values.config.agentConcurrency }}
- { name: NEXUS_AGENT_CONCURRENCY, value: {{ . | toString | quote }} }
{{- end }}
{{- if .Values.agentReleases.existingClaim }}
- { name: NEXUS_AGENT_RELEASES_DIR, value: /releases }
{{- end }}
{{- $secret := include "nexus.secretName" . }}
- name: NEXUS_DATABASE_URL
  valueFrom: { secretKeyRef: { name: {{ $secret }}, key: databaseUrl } }
- name: NEXUS_SEAL_KEYS
  valueFrom: { secretKeyRef: { name: {{ $secret }}, key: sealKeys } }
- name: NEXUS_SMTP_URL
  valueFrom: { secretKeyRef: { name: {{ $secret }}, key: smtpUrl } }
- name: NEXUS_METRICS_TOKEN
  valueFrom: { secretKeyRef: { name: {{ $secret }}, key: metricsToken } }
{{- range $env, $key := dict "NEXUS_AGENT_RELEASE_KEYS" "agentReleaseKeys" "NEXUS_APNS_TEAM_ID" "apnsTeamId" "NEXUS_APNS_KEY_ID" "apnsKeyId" "NEXUS_APNS_KEY" "apnsKey" "NEXUS_FCM_SERVICE_ACCOUNT" "fcmServiceAccount" }}
- name: {{ $env }}
  valueFrom: { secretKeyRef: { name: {{ $secret }}, key: {{ $key }}, optional: true } }
{{- end }}
{{- range $k, $v := .Values.config.extraEnv }}
- { name: {{ $k }}, value: {{ $v | toString | quote }} }
{{- end }}
{{- end }}

{{/* Spread pods across zones and nodes, so one failure never takes every replica. */}}
{{- define "nexus.spread" -}}
{{- $ := index . 0 -}}{{- $c := index . 1 -}}
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        {{- include "nexus.selector" (list $ $c) | nindent 8 }}
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        {{- include "nexus.selector" (list $ $c) | nindent 8 }}
{{- end }}
