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
{{- /* G0 M32 D969: the clusters, reviewed with the server's own projected token. Not for the migrate Job, which mounts none of it. */ -}}
{{- if and $v.identity.kubernetesClusters (ne .role "migrate") -}}
{{- $clusters := list -}}
{{- range $v.identity.kubernetesClusters -}}
{{- $clusters = append $clusters (dict "name" .name "api_server" (default "https://kubernetes.default.svc" .apiServer)
      "ca_file" (printf "%s/ca.crt" (include "pantherclaw.kubeDir" .)) "token_file" (printf "%s/token" (include "pantherclaw.kubeDir" .))
      "allowed_prefixes" (required "identity.kubernetesClusters[].allowedPrefixes is required" .allowedPrefixes)
      "orgs" (required "identity.kubernetesClusters[].orgs is required" .orgs)
      ) -}}
{{- if eq $role "api" -}}{{- $_ := set (last $clusters) "webhook_secret_file" (printf "%s/webhook-%s" $s .name) -}}{{- end -}}
{{- end -}}
{{- $_ := set $cfg "identity" (dict "kubernetes_clusters" $clusters) -}}
{{- end -}}
{{- /* G0 M32 D967, D969: the admission listener, on the API only. */ -}}
{{- if and $v.admission.enabled (ne .role "worker") (ne .role "migrate") -}}
{{- $_ := set $cfg "admission" (dict "listen" (printf "0.0.0.0:%d" (int $v.admission.port))
      "tls_cert_file" (printf "%s/admission-tls.crt" $s) "tls_key_file" (printf "%s/admission-tls.key" $s)
      "edge_image_digests" $v.admission.edgeImageDigests "probe_image_digests" $v.admission.probeImageDigests) -}}
{{- end -}}
{{- toPrettyJson $cfg -}}
{{- end -}}

{{/* G0 M32 D969: where the server's projected reviewer token and the cluster CA are mounted. */}}
{{- define "pantherclaw.kubeDir" -}}/var/run/pantherclaw/kube{{- end -}}

{{/* The webhook Secret's name. */}}
{{- define "pantherclaw.webhookSecretName" -}}{{ include "pantherclaw.fullname" . }}-webhook{{- end -}}

{{/*
G0 M32 D969a: the webhook secret of a cluster (dict "root" $ "cluster" NAME).
It is reused from the chart's Secret when it exists (lookup on upgrade),
else generated, and cached for the rest of this render so that the Secret
and the webhook path hold the same value.
*/}}
{{- define "pantherclaw.webhookSecret" -}}
{{- $root := .root -}}
{{- if not (hasKey $root.Values "__pcWebhookSecrets") -}}
{{- $_ := set $root.Values "__pcWebhookSecrets" dict -}}
{{- end -}}
{{- $cache := get $root.Values "__pcWebhookSecrets" -}}
{{- if not (hasKey $cache .cluster) -}}
{{- $value := "" -}}
{{- $existing := lookup "v1" "Secret" $root.Release.Namespace (include "pantherclaw.webhookSecretName" $root) -}}
{{- if and $existing $existing.data -}}
{{- with index $existing.data .cluster -}}{{- $value = b64dec . -}}{{- end -}}
{{- end -}}
{{- if not $value -}}{{- $value = randAlphaNum 48 -}}{{- end -}}
{{- $_ := set $cache .cluster $value -}}
{{- end -}}
{{- get $cache .cluster -}}
{{- end -}}

{{/* An image by digest when set, else by tag (default appVersion). Arguments: dict "root" $ "image" VALUES. */}}
{{- define "pantherclaw.image" -}}
{{- if .image.digest -}}
{{- printf "%s@%s" .image.repository .image.digest -}}
{{- else -}}
{{- printf "%s:%s" .image.repository (default .root.Chart.AppVersion .image.tag) -}}
{{- end -}}
{{- end -}}

{{/* G0 M32 D969: the edge and probe images of the probe CronJob, by digest; the digest defaults to the first admitted one. */}}
{{- define "pantherclaw.edgeImage" -}}
{{- $d := default (first .Values.admission.edgeImageDigests) .Values.probe.edgeImage.digest -}}
{{- printf "%s@%s" .Values.probe.edgeImage.repository (required "probe.edgeImage.digest or admission.edgeImageDigests is required" $d) -}}
{{- end -}}
{{- define "pantherclaw.probeImage" -}}
{{- $d := default (first .Values.admission.probeImageDigests) .Values.probe.image.digest -}}
{{- printf "%s@%s" .Values.probe.image.repository (required "probe.image.digest or admission.probeImageDigests is required" $d) -}}
{{- end -}}

{{/* G0 M32 D965a: the API URL the edges of agent pods call. */}}
{{- define "pantherclaw.agentAPIURL" -}}
{{- printf "https://%s:%d" .Values.api.service.agentHostname (int .Values.api.service.port) -}}
{{- end -}}

{{/*
G0 M32 D966, D970a: the edge configuration of a namespace (dict "root" $
"hosts" MAP), pantherclaw.edge/v1 in kubernetes mode.
*/}}
{{- define "pantherclaw.edgeConfig" -}}
{{- $v := .root.Values -}}
{{- $edge := dict "format" "pantherclaw.edge/v1" "mode" "kubernetes" "listen" "127.0.0.1:3128"
      "gateway_url" (include "pantherclaw.agentGatewayURL" .root) "hosts" .hosts
      "kube_token_file" "/var/run/pantherclaw/edge/token" "api_url" (include "pantherclaw.agentAPIURL" .root) "ca_dir" "/pc-edge" -}}
{{- with $v.gateway.tlsCAPin }}{{- $_ := set $edge "gateway_ca_pin" . }}{{- end -}}
{{- toPrettyJson $edge -}}
{{- end -}}

{{/*
G0 M32 D969, D970, D970a: a daily probe CronJob (dict "root" $ "name" NAME
"namespace" NS "clusterIP" GATEWAY_IP "serviceAccount" SA "org" ORG "args" LIST "hosts" MAP):
an agent pod whose app container is the probe.
*/}}
{{- define "pantherclaw.probeCronJob" -}}
{{- $v := .root.Values }}
apiVersion: batch/v1
kind: CronJob
metadata:
  name: {{ .name }}
  namespace: {{ .namespace }}
  labels:
    {{- include "pantherclaw.labels" .root | nindent 4 }}
spec:
  schedule: {{ $v.probe.schedule | quote }}
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 1
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      backoffLimit: 0
      activeDeadlineSeconds: 900
      template:
        metadata:
          labels:
            app.kubernetes.io/name: {{ .name }}
            app.kubernetes.io/instance: {{ .root.Release.Name }}
        spec:
          {{- include "pantherclaw.agentPodSpec" (dict "root" .root "clusterIP" .clusterIP "serviceAccount" .serviceAccount "org" .org) | nindent 10 }}
          restartPolicy: Never
          containers:
            - name: probe
              image: {{ include "pantherclaw.probeImage" .root }}
              imagePullPolicy: IfNotPresent
              args: {{ toJson .args }}
              env:
                {{- include "pantherclaw.agentEnv" .root | nindent 16 }}
                {{- include "pantherclaw.probeEnv" .root | nindent 16 }}
                - name: PC_AGENT_HOSTS
                  value: {{ join "," (keys .hosts | sortAlpha) | quote }}
              securityContext:
                {{- toYaml $v.securityContext | nindent 16 }}
              volumeMounts:
                - name: pc-edge
                  mountPath: /pc-edge
                  readOnly: true
{{- end -}}

{{/* G0 M32 D970a: the probe's environment. */}}
{{- define "pantherclaw.probeEnv" -}}
- name: PC_HOST_IP
  valueFrom:
    fieldRef:
      fieldPath: status.hostIP
- name: PC_CANARY_IP
  value: {{ .Values.probe.canary.clusterIP | quote }}
{{- end -}}

{{/* G0 M32 D966, D969: the gateway URL agent pods call. */}}
{{- define "pantherclaw.agentGatewayURL" -}}
{{- printf "https://%s:%d" .Values.gateway.hostname (int .Values.gateway.port) -}}
{{- end -}}

{{/* G0 M32 D964: the label keys of a protected namespace. */}}
{{- define "pantherclaw.protectLabel" -}}pantherclaw.dev/protect{{- end -}}
{{- define "pantherclaw.orgLabel" -}}pantherclaw.dev/org{{- end -}}

{{/*
G0 M32 D966, D967, D969: the pod-level part of an agent pod (dict "root" $
"clusterIP" IP "serviceAccount" NAME "org" ORG): no service account token,
the gateway hostname pinned by hostAliases (no DNS, FQ32-3), the edge as the
one native sidecar with the projected token (audience pantherclaw:<org>)
mounted into it alone, and the /pc-edge emptyDir its CA certificate goes to.
examples/agent-pod.yaml is the same shape.
*/}}
{{- define "pantherclaw.agentPodSpec" -}}
{{- $v := .root.Values -}}
serviceAccountName: {{ .serviceAccount }}
automountServiceAccountToken: false
enableServiceLinks: false
securityContext:
  {{- toYaml $v.podSecurityContext | nindent 2 }}
hostAliases:
  - ip: {{ .clusterIP | quote }}
    hostnames: [{{ $v.gateway.hostname | quote }}]
  - ip: {{ $v.api.service.clusterIP | quote }}
    hostnames: [{{ $v.api.service.agentHostname | quote }}]
initContainers:
  - name: pantherclaw-edge
    image: {{ include "pantherclaw.edgeImage" .root }}
    imagePullPolicy: IfNotPresent
    restartPolicy: Always
    args: ["--config", "/etc/pantherclaw-edge/edge.json"]
    env:
      - name: PC_POD_NAME
        valueFrom:
          fieldRef:
            fieldPath: metadata.name
      - name: PC_NAMESPACE
        valueFrom:
          fieldRef:
            fieldPath: metadata.namespace
    securityContext:
      {{- toYaml $v.securityContext | nindent 6 }}
    volumeMounts:
      - name: edge-config
        mountPath: /etc/pantherclaw-edge
        readOnly: true
      - name: edge-token
        mountPath: /var/run/pantherclaw/edge
        readOnly: true
      - name: pc-edge
        mountPath: /pc-edge
volumes:
  - name: edge-config
    configMap:
      name: pantherclaw-edge
  - name: edge-token
    projected:
      sources:
        - serviceAccountToken:
            path: token
            audience: {{ printf "pantherclaw:%s" .org | quote }}
            expirationSeconds: 3600
  - name: pc-edge
    emptyDir:
      medium: Memory
      sizeLimit: 1Mi
{{- end -}}

{{/* G0 M32 D969: an agent container's environment: every request through the edge, trusting its CA. */}}
{{- define "pantherclaw.agentEnv" -}}
- name: HTTPS_PROXY
  value: http://127.0.0.1:3128
- name: HTTP_PROXY
  value: http://127.0.0.1:3128
- name: SSL_CERT_FILE
  value: /pc-edge/ca.crt
{{- end -}}

{{/*
G0 M32 D969: the server's mounts for Kubernetes (dict "root" $ "role" "api|worker"):
its projected reviewer token with the cluster CA. The kubelet writes a
projected token 0600 and owned by the pod's runAsUser, as secret files must
be (config.ReadSecretFile). The webhook secrets and the admission
certificate are staged like every other secret (D42, D969b): see
pantherclaw.kubeStagedKeys.
*/}}
{{- define "pantherclaw.kubeMounts" -}}
{{- $v := .root.Values -}}
{{- if $v.identity.kubernetesClusters }}
- name: kube
  mountPath: {{ include "pantherclaw.kubeDir" . }}
  readOnly: true
{{- end }}
{{- end -}}

{{/*
G0 M32 D969b: the API's staged Kubernetes secrets, as stage-secrets keys
(list of dict "volume" "key" "as"): each cluster's webhook secret as
webhook-<cluster>, and the admission certificate pair as admission-tls.crt
and admission-tls.key, like api.tls. A changed value rolls the API pods
(checksum/admission-webhook).
*/}}
{{- define "pantherclaw.kubeStagedKeys" -}}
{{- $v := .Values -}}
{{- $keys := list -}}
{{- range $v.identity.kubernetesClusters -}}
{{- $keys = append $keys (dict "volume" "webhook" "key" .name "as" (printf "webhook-%s" .name)) -}}
{{- end -}}
{{- if $v.admission.enabled -}}
{{- $keys = append $keys (dict "volume" "admission-tls" "key" "tls.crt" "as" "admission-tls.crt") -}}
{{- $keys = append $keys (dict "volume" "admission-tls" "key" "tls.key" "as" "admission-tls.key") -}}
{{- end -}}
{{- toJson $keys -}}
{{- end -}}

{{/* G0 M32 D969b: the sha256 of every rendered webhook secret value, so a new value rolls the API pods. */}}
{{- define "pantherclaw.webhookChecksum" -}}
{{- $vals := list -}}
{{- range .Values.identity.kubernetesClusters -}}
{{- $vals = append $vals (printf "%s=%s" .name (include "pantherclaw.webhookSecret" (dict "root" $ "cluster" .name))) -}}
{{- end -}}
{{- join "\n" $vals | sha256sum -}}
{{- end -}}

{{- define "pantherclaw.kubeVolumes" -}}
{{- $v := .root.Values -}}
{{- if $v.identity.kubernetesClusters }}
- name: kube
  projected:
    sources:
      - serviceAccountToken:
          path: token
          expirationSeconds: {{ int $v.identity.reviewerTokenExpirationSeconds }}
      - configMap:
          name: kube-root-ca.crt
          items:
            - key: ca.crt
              path: ca.crt
{{- if eq .role "api" }}
- name: webhook
  secret:
    secretName: {{ include "pantherclaw.webhookSecretName" .root }}
{{- end }}
{{- end }}
{{- if and $v.admission.enabled (eq .role "api") }}
- name: admission-tls
  secret:
    secretName: {{ required "admission.tls.existingSecret is required when admission.enabled" $v.admission.tls.existingSecret }}
{{- end }}
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
