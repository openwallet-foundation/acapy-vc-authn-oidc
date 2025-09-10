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
Selector acapy labels
*/}}
{{- define "vc-authn-oidc.acapy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vc-authn-oidc.acapy.name" . }}
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
vc-authn-oidc labels
*/}}
{{- define "vc-authn-oidc.labels" -}}
{{ include "common.labels" . }}
{{ include "vc-authn-oidc.selectorLabels" . }}
{{- end }}

{{/*
Return the proper vc-authn-oidc image name
*/}}
{{- define "vc-authn-oidc.image" -}}
{{ include "common.images.image" ( dict "imageRoot" .Values.image "global" .Values.global "chart" .Chart ) }}
{{- end -}}

{{/*
Generate host name based on chart name + domain suffix
*/}}
{{- define "vc-authn-oidc.host" -}}
{{- include "global.fullname" . }}{{ .Values.global.ingressSuffix -}}
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

{{/* Define AcaPy base name */}}
{{- define "vc-authn-oidc.acapy.name" -}}
{{- default "acapy" .Values.acapy.nameOverride -}}
{{- end -}}

{{/*
Create a default fully qualified acapy name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "vc-authn-oidc.acapy.fullname" -}}
{{- printf "%s-%s" (include "global.fullname" .) (include "vc-authn-oidc.acapy.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Return the acapy secret name
*/}}
{{- define "vc-authn-oidc.acapy.secretName" -}}
    {{- if .Values.acapy.secrets.api.existingSecret -}}
        {{- .Values.acapy.secrets.api.existingSecret -}}
    {{- else -}}
          {{- printf "%s-%s-api" (include "global.fullname" .) (include "vc-authn-oidc.acapy.name" .) | trunc 63 | trimSuffix "-" -}}
    {{- end -}}
{{- end -}}

{{/*
generate hosts if not overriden
*/}}
{{- define "vc-authn-oidc.acapy.host" -}}
    {{- printf "%s-%s%s" (include "global.fullname" .) (include "vc-authn-oidc.acapy.name" .) .Values.global.ingressSuffix -}}
{{- end -}}

{{/*
Create URL based on hostname and TLS status
*/}}
{{- define "vc-authn-oidc.acapy.agent.url" -}}
{{- if .Values.useHTTPS -}}
{{- printf "https://%s" (include "vc-authn-oidc.acapy.host" .) }}
{{- else -}}
{{- printf "http://%s" (include "vc-authn-oidc.acapy.host" .) }}
{{- end -}}
{{- end }}

{{/*
generate admin url (internal)
*/}}
{{- define "vc-authn-oidc.acapy.admin.url" -}}
    http://{{ include "vc-authn-oidc.acapy.fullname" . }}:{{ .Values.acapy.service.ports.admin }}
{{- end -}}

{{/*
Generate hosts for acapy admin if not overriden
*/}}
{{- define "vc-authn-oidc.acapy.admin.host" -}}
   {{- printf "%s-%s-admin%s" (include "global.fullname" .) (include "vc-authn-oidc.acapy.name" .) .Values.global.ingressSuffix -}}
{{- end -}}
