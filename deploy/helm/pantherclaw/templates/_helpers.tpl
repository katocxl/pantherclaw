{{/*
SPDX-License-Identifier: BUSL-1.1
Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
*/}}

{{- define "pantherclaw.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "pantherclaw.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "pantherclaw.selector" -}}
app.kubernetes.io/name: {{ .root.Chart.Name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* The server image: by digest when set, else by tag (default appVersion). */}}
{{- define "pantherclaw.serverImage" -}}
{{- $i := .Values.image.server -}}
{{- if $i.digest -}}
{{- printf "%s@%s" $i.repository $i.digest -}}
{{- else -}}
{{- printf "%s:%s" $i.repository (default .Chart.AppVersion $i.tag) -}}
{{- end -}}
{{- end -}}

{{/*
server.json for a role (dict "root" $ "role" "api|worker|migrate"). Secrets
are file paths under /etc/pantherclaw/secrets, staged 0400 by the
stage-secrets init container (G0 M13 D42).
*/}}
{{- define "pantherclaw.serverConfig" -}}
{{- $v := .root.Values -}}
{{- $s := "/etc/pantherclaw/secrets" -}}
{{- $db := dict "host" $v.database.host "port" (int $v.database.port) "name" $v.database.name "sslmode" $v.database.sslmode
      "sslrootcert" (printf "%s/ca.crt" $s) "app_user" "pc_app" "migrator_user" "pc_migrator" "retention_user" "pc_retention"
      "max_conns" (int $v.database.maxConns) "replication" $v.database.replication -}}
{{- with $v.database.hosts -}}{{- $_ := set $db "hosts" . -}}{{- end -}}
{{- if eq .role "migrate" -}}
{{- $_ := set $db "migrator_password_file" (printf "%s/migrator-password" $s) -}}
{{- /* Named for validation only: migrate up reads the migrator's file alone, and the Job never gets the app's password. */ -}}
{{- $_ := set $db "app_password_file" (printf "%s/app-password" $s) -}}
{{- else -}}
{{- $_ := set $db "app_password_file" (printf "%s/app-password" $s) -}}
{{- $_ := set $db "retention_password_file" (printf "%s/retention-password" $s) -}}
{{- end -}}
{{- $role := .role -}}
{{- if eq .role "migrate" -}}{{- $role = "api" -}}{{- end -}}
{{- $providers := list -}}
{{- range $v.oidc.providers -}}
{{- $providers = append $providers (dict "name" .name "issuer" .issuer "client_id" .clientID "client_secret_file" (printf "%s/oidc-%s" $s .name)) -}}
{{- end -}}
{{- $http := dict "addr" "0.0.0.0:8080" -}}
{{- if $v.api.tls.existingSecret -}}
{{- $_ := set $http "tls_cert_file" (printf "%s/tls.crt" $s) -}}
{{- $_ := set $http "tls_key_file" (printf "%s/tls.key" $s) -}}
{{- else -}}
{{- $_ := set $http "plaintext_behind_proxy" true -}}
{{- end -}}
{{- if $v.api.trustedProxies -}}
{{- $_ := set $http "trusted_proxies" $v.api.trustedProxies -}}
{{- end -}}
{{- $gwHost := first $v.gatewayAPI.hostnames -}}
{{- $cfg := dict "role" $role "deployment" $v.deployment "log" (dict "level" $v.logLevel) "http" $http "database" $db
      "kek_files" (list (printf "%s/kek" $s)) "worker_concurrency" (int $v.worker.concurrency)
      "gateway_api" (dict "addr" (printf "0.0.0.0:%d" (int $v.gatewayAPI.port)) "hostnames" $v.gatewayAPI.hostnames
        "url" (printf "https://%s:%d" $gwHost (int $v.gatewayAPI.port)))
      "auth" (dict "public_url" $v.publicURL "api_key_env" "live" "oidc_providers" $providers) -}}
{{- if eq .role "worker" -}}
{{- $_ := set $cfg "health" (dict "addr" (printf "0.0.0.0:%d" (int $v.worker.healthPort))) -}}
{{- end -}}
{{- toPrettyJson $cfg -}}
{{- end -}}

{{/* The stage-secrets init container (G0 M13 D42). Arguments: dict "root" $ "keys" (list of dict "volume" "key" "as"). */}}
{{- define "pantherclaw.stageSecrets" -}}
- name: stage-secrets
  image: {{ include "pantherclaw.serverImage" .root }}
  imagePullPolicy: {{ .root.Values.image.pullPolicy }}
  args: ["secrets", "stage", "--from", "/secrets-src", "--to", "/secrets"]
  securityContext:
    {{- toYaml .root.Values.securityContext | nindent 4 }}
  volumeMounts:
    - name: secrets
      mountPath: /secrets
    {{- range .keys }}
    # One key per subPath mount: a regular file, never the Secret
    # volume's symlinks.
    - name: {{ .volume }}
      mountPath: /secrets-src/{{ .as }}
      subPath: {{ .key }}
      readOnly: true
    {{- end }}
{{- end -}}

{{/* Environment shared by the API and worker containers. */}}
{{- define "pantherclaw.env" -}}
- name: PC_MAINTENANCE_HOLD
  value: {{ .Values.maintenanceHold | quote }}
{{- end -}}
