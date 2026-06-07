{{/*
Expand the name of the chart.
*/}}
{{- define "accessgate.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "accessgate.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart name and version label.
*/}}
{{- define "accessgate.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "accessgate.labels" -}}
helm.sh/chart: {{ include "accessgate.chart" . }}
{{ include "accessgate.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: accessgate
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Base selector labels (shared by all components).
*/}}
{{- define "accessgate.selectorLabels" -}}
app.kubernetes.io/name: {{ include "accessgate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Component-scoped names and labels. Call with a dict:
  (dict "context" . "component" "auth")
*/}}
{{- define "accessgate.componentFullname" -}}
{{- printf "%s-%s" (include "accessgate.fullname" .context) .component | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "accessgate.componentLabels" -}}
{{ include "accessgate.labels" .context }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- define "accessgate.componentSelectorLabels" -}}
{{ include "accessgate.selectorLabels" .context }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Service account name.
*/}}
{{- define "accessgate.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "accessgate.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Name of the Secret holding sensitive config (cookie signing secret, OIDC
client secret, admin secret). Either an existing Secret or the chart-created one.
*/}}
{{- define "accessgate.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- printf "%s-secrets" (include "accessgate.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Resolve an image reference, honoring global.imageRegistry. Call with a dict:
  (dict "context" . "image" .Values.auth.image)
Tag falls back to .Chart.AppVersion when image.tag is empty.
*/}}
{{- define "accessgate.image" -}}
{{- $registry := .context.Values.global.imageRegistry -}}
{{- $repo := .image.repository -}}
{{- $tag := .image.tag | default .context.Chart.AppVersion -}}
{{- if $registry }}
{{- printf "%s/%s:%s" $registry $repo $tag }}
{{- else }}
{{- printf "%s:%s" $repo $tag }}
{{- end }}
{{- end }}

{{/*
Image pull secrets (merge global + top-level).
*/}}
{{- define "accessgate.imagePullSecrets" -}}
{{- $secrets := concat (.Values.global.imagePullSecrets | default list) (.Values.imagePullSecrets | default list) -}}
{{- if $secrets }}
imagePullSecrets:
{{- range $secrets }}
  - name: {{ .name | default . }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Resolved Redis connection URL for accessgate-auth.
  - redis.enabled=true  → in-cluster Bitnami Redis master service.
  - redis.enabled=false → externalRedis.url (must be set).
*/}}
{{- define "accessgate.redisURL" -}}
{{- if .Values.redis.enabled -}}
{{- printf "redis://%s-redis-master:6379" .Release.Name -}}
{{- else -}}
{{- required "redis.enabled=false requires externalRedis.url to be set" .Values.externalRedis.url -}}
{{- end -}}
{{- end }}

{{/*
Resolved auth_url the proxy uses to reach accessgate-auth. Falls back to the
in-cluster auth Service when proxy.config.authURL is empty.
*/}}
{{- define "accessgate.authURL" -}}
{{- if .Values.proxy.config.authURL -}}
{{- .Values.proxy.config.authURL -}}
{{- else -}}
{{- printf "http://%s:%d" (include "accessgate.componentFullname" (dict "context" . "component" "auth")) (int .Values.auth.service.port) -}}
{{- end -}}
{{- end }}
