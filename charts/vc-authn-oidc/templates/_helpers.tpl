{{/*
Expand the name of the chart.
*/}}
{{- define "global.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "global.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "global.fullname" -}}
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
Common labels
*/}}
{{- define "common.labels" -}}
app: {{ include "global.name" . }}
helm.sh/chart: {{ include "global.chart" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end }}

{{/*
Selector common labels
*/}}
{{- define "common.selectorLabels" -}}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create a default fully qualified acapy name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "acapy.fullname" -}}
{{ template "global.fullname" . }}-agent
{{- end -}}

{{/*
Selector acapy labels
*/}}
{{- define "acapy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "acapy.fullname" . }}
{{ include "common.selectorLabels" . }}
{{- end -}}

{{/*
Selector labels
*/}}
{{- define "vc-authn-oidc.selectorLabels" -}}
app.kubernetes.io/name: {{ include "global.name" . }}
{{ include "common.selectorLabels" . }}
{{- end }}

{{/*
Agent labels
*/}}
{{- define "acapy.labels" -}}
{{ include "common.labels" . }}
{{ include "acapy.selectorLabels" . }}
{{- end -}}

{{/*
Agent tails pvc name.
*/}}
{{- define "acapy.tails.pvc.name" -}}
{{ template "acapy.fullname" . }}-tails
{{- end -}}

{{/*
vc-authn-oidc labels
*/}}
{{- define "vc-authn-oidc.labels" -}}
{{ include "common.labels" . }}
{{ include "vc-authn-oidc.selectorLabels" . }}
{{- end }}

{{/*
Generate host name based on chart name + domain suffix
*/}}
{{- define "vc-authn-oidc.host" -}}
{{- include "global.fullname" . }}{{ .Values.ingressSuffix -}}
{{- end }}

{{/*
Add TLS annotation for OpenShift route
*/}}
{{- define "vc-authn-oidc.openshift.route.tls" -}}
{{- if (.Values.route.tls.enabled) -}}
tls:
  insecureEdgeTerminationPolicy: {{ .Values.route.tls.insecureEdgeTerminationPolicy }}
  termination: {{ .Values.route.tls.termination }}
{{- end -}}
{{- end -}}

{{/*
Create the name of the service account to use
*/}}
{{- define "vc-authn-oidc.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "global.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create URL based on hostname and TLS status
*/}}
{{- define "vc-authn-oidc.url" -}}
{{- if .Values.useHTTPS -}}
{{- printf "https://%s" (include "vc-authn-oidc.host" .) | quote }}
{{- else -}}
{{- printf "http://%s" (include "vc-authn-oidc.host" .) | quote }}
{{- end -}}
{{- end }}

{{/*
Returns a secret if it already in Kubernetes, otherwise it creates
it randomly.

Usage:
{{ include "getOrGeneratePass" (dict "Namespace" .Release.Namespace "Kind" "Secret" "Name" (include "vc-authn-oidc.databaseSecretName" .) "Key" "mongodb-root-password" "Length" 32) }}

*/}}
{{- define "getOrGeneratePass" }}
{{- $len := (default 16 .Length) | int -}}
{{- $obj := (lookup "v1" .Kind .Namespace .Name).data -}}
{{- if $obj }}
{{- index $obj .Key -}}
{{- else if (eq (lower .Kind) "secret") -}}
{{- randAlphaNum $len | b64enc -}}
{{- else -}}
{{- randAlphaNum $len -}}
{{- end -}}
{{- end }}

{{/*
Define the name of the database secret to use
*/}}
{{- define "vc-authn-oidc.databaseSecretName" -}}
{{- if (empty .Values.database.existingSecret) -}}
{{- printf "%s-%s" .Release.Name "mongodb" | trunc 63 | trimSuffix "-" }}
{{- else -}}
{{- .Values.database.existingSecret -}}
{{- end -}}
{{- end }}

{{/*
Return true if a database secret should be created
*/}}
{{- define "vc-authn-oidc.database.createSecret" -}}
{{- if not .Values.database.existingSecret -}}
{{- true -}}
{{- end -}}
{{- end -}}

{{/*
Create the name of the api key secret to use
*/}}
{{- define "vc-authn-oidc.apiSecretName" -}}
{{- if (empty .Values.auth.api.existingSecret) }}
    {{- printf "%s-%s" .Release.Name "api-key" | trunc 63 | trimSuffix "-" }}
{{- else -}}
    {{- .Values.auth.api.existingSecret }}
{{- end -}}
{{- end }}

{{/*
Return true if the api-secret should be created
*/}}
{{- define "vc-authn-oidc.api.createSecret" -}}
{{- if (empty .Values.auth.token.privateKey.existingSecret) }}
    {{- true -}}
{{- end -}}
{{- end }}

{{/*
Return the secret with vc-authn-oidc token private key
*/}}
{{- define "vc-authn-oidc.token.secretName" -}}
    {{- if .Values.auth.token.privateKey.existingSecret -}}
        {{- .Values.auth.token.privateKey.existingSecret -}}
    {{- else -}}
        {{- printf "%s-jwt-token" (include "global.fullname" .) | trunc 63 | trimSuffix "-" -}}
    {{- end -}}
{{- end -}}

{{/*
Return true if a secret object should be created for the vc-authn-oidc token private key
*/}}
{{- define "vc-authn-oidc.token.createSecret" -}}
{{- if (empty .Values.auth.token.privateKey.existingSecret) }}
    {{- true -}}
{{- end -}}
{{- end -}}

{{/*
Generate token private key
*/}}
{{- define "vc-authn-oidc.token.jwtToken" -}}
{{- if (include "vc-authn-oidc.token.createSecret" .) -}}
{{- $jwtToken := lookup "v1" "Secret" .Release.Namespace (printf "%s-jwt-token" (include "global.fullname" .) | trunc 63 | trimSuffix "-" ) -}}
{{- if $jwtToken -}}
{{ index $jwtToken "data" "jwt-token.pem" | b64dec }}
{{- else -}}
{{ genPrivateKey "rsa" }}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Return true if a secret object should be created for the vc-authn-oidc token private key
*/}}
{{- define "acapy.createSecret" -}}
{{- if (empty .Values.acapy.existingSecret) }}
    {{- true -}}
{{- end -}}
{{- end -}}

{{/*
Return the secret with vc-authn-oidc token private key
*/}}
{{- define "acapy.secretName" -}}
    {{- if .Values.acapy.existingSecret -}}
        {{- .Values.acapy.existingSecret -}}
    {{- else -}}
        {{- printf "%s-acapy-secret" (include "global.fullname" .) | trunc 63 | trimSuffix "-" -}}
    {{- end -}}
{{- end -}}

{{/*
Create a default fully qualified postgresql name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "acapy.database.secretName" -}}
{{- if .Values.acapy.walletStorageCredentials.existingSecret -}}
{{- .Values.acapy.walletStorageCredentials.existingSecret }}
{{- else -}}
{{ template "global.fullname" . }}-postgresql
{{- end -}}
{{- end -}}

{{/*
Return acapy label
*/}}
{{- define "acapy.label" -}}
{{- if .Values.acapy.labelOverride -}}
    {{- .Values.acapy.labelOverride }} 
{{- else -}} 
    {{- .Release.Name }}     
{{- end -}}
{{- end -}}

{{/*
Create URL based on hostname and TLS status
*/}}
{{- define "acapy.agent.url" -}}
{{- if .Values.useHTTPS -}}
{{- printf "https://%s" (include "acapy.host" .) }}
{{- else -}}
{{- printf "http://%s" (include "acapy.host" .) }}
{{- end -}}
{{- end }}

{{/*
generate hosts if not overriden
*/}}
{{- define "acapy.host" -}}
{{- if .Values.acapy.enabled }}
{{- include "global.fullname" . }}-agent{{ .Values.ingressSuffix -}}
{{- else }}
    {{ .Values.acapy.agentUrl }}
{{- end }}
{{- end -}}

{{/*
generate admin url (internal)
*/}}
{{- define "acapy.internal.admin.url" -}}
http://{{- include "acapy.fullname" . }}:{{.Values.acapy.service.adminPort }}
{{- end -}}

{{/*
Generate hosts for acapy admin if not overriden
*/}}
{{- define "acapy.admin.host" -}}
{{- if .Values.acapy.enabled }}
    {{- include "global.fullname" . }}-agent-admin{{ .Values.ingressSuffix -}}
{{- else }}
    {{ .Values.acapy.adminUrl }}
{{- end }}
{{- end -}}

{{/*
Create a default fully qualified app name for the postgres requirement.
*/}}
{{- define "global.postgresql.fullname" -}}
{{- if .Values.postgresql.fullnameOverride }}
{{- .Values.postgresql.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $postgresContext := dict "Values" .Values.postgresql "Release" .Release "Chart" (dict "Name" "postgresql") -}}
{{ template "postgresql.v1.primary.fullname" $postgresContext }}
{{- end -}}
{{- end -}}

{{/*
Generate acapy wallet storage config
*/}}
{{- define "acapy.walletStorageConfig" -}}
{{- if .Values.acapy.walletStorageConfig.json -}}
    {{- .Values.acapy.walletStorageConfig.json -}}
{{- else if .Values.acapy.walletStorageConfig.url -}}
    '{"url":"{{ .Values.acapy.walletStorageConfig.url }}","max_connections":"{{ .Values.acapy.walletStorageConfig.max_connection | default 10 }}", "wallet_scheme":"{{ .Values.acapy.walletStorageConfig.wallet_scheme }}"}'
{{- else if .Values.postgresql.enabled -}}
    '{"url":"{{ include "global.postgresql.fullname" . }}:{{ .Values.postgresql.primary.service.ports.postgresql }}","max_connections":"{{ .Values.acapy.walletStorageConfig.max_connections }}","wallet_scheme":"{{ .Values.acapy.walletStorageConfig.wallet_scheme }}"}'
{{- else -}}
    ''
{{ end }}
{{- end -}}

{{/*
Generate acapy wallet storage credentials
*/}}
{{- define "acapy.walletStorageCredentials" -}}
{{- if .Values.acapy.walletStorageCredentials.json -}}
    {{- .Values.acapy.walletStorageCredentials.json -}}
{{- else if .Values.postgresql.enabled -}}
    '{"account":"{{ .Values.postgresql.auth.username }}","password":"$(POSTGRES_PASSWORD)","admin_account":"{{ .Values.acapy.walletStorageCredentials.admin_account }}","admin_password":"$(POSTGRES_POSTGRES_PASSWORD)"}'
{{- else -}}
    '{"account":"{{ .Values.acapy.walletStorageCredentials.account | default "acapy" }}","password":"$(POSTGRES_PASSWORD)","admin_account":"{{ .Values.acapy.walletStorageCredentials.admin_account }}","admin_password":"$(POSTGRES_POSTGRES_PASSWORD)"}'
{{- end -}}
{{- end -}}

{{/*
Create the name of the acapy service account to use
*/}}
{{- define "acapy.serviceAccountName" -}}
{{- if .Values.acapy.serviceAccount.create }}
{{- default (include "acapy.fullname" .) .Values.acapy.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.acapy.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Return true if the seed secret should be created
*/}}
{{- define "acapy.seed.createSecret" -}}
{{- if not .Values.acapy.agentSeed.existingSecret -}}
{{- true -}}
{{- end -}}
{{- end -}}
