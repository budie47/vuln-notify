#!/usr/bin/env bash
# Creates the Entra identity GitHub Actions uses to deploy (OIDC: no password stored in GitHub)
# and grants it access to the resource group. Safe to run more than once.
#
#   bash infra/setup-github-identity.sh [resource-group] [owner/repo]
set -euo pipefail
RG=${1:-rg-vuln-notify}
REPO=${2:-budie47/vuln-notify}

RG_ID=$(az group show -n "$RG" --query id -o tsv)
CI_APP=$(az ad app list --display-name vuln-notify-github --query "[0].appId" -o tsv)
[ -n "$CI_APP" ] || CI_APP=$(az ad app create --display-name vuln-notify-github --query appId -o tsv)
CI_SP=$(az ad sp show --id "$CI_APP" --query id -o tsv 2>/dev/null || az ad sp create --id "$CI_APP" --query id -o tsv)

# GitHub jobs that use the "production" environment of $REPO may sign in as this app.
if ! az ad app federated-credential list --id "$CI_APP" --query "[].name" -o tsv | grep -qx github-production; then
  az ad app federated-credential create --id "$CI_APP" -o none --parameters "{
    \"name\": \"github-production\",
    \"issuer\": \"https://token.actions.githubusercontent.com\",
    \"subject\": \"repo:$REPO:environment:production\",
    \"audiences\": [\"api://AzureADTokenExchange\"]
  }"
fi

# Contributor: create/update resources. RBAC Administrator: the Bicep assigns roles to the app's
# managed identity (registry pull, Key Vault read) and to the SMTP app.
for role in "Contributor" "Role Based Access Control Administrator"; do
  if [ -z "$(az role assignment list --assignee "$CI_SP" --scope "$RG_ID" --role "$role" --query '[0].id' -o tsv)" ]; then
    az role assignment create --assignee-object-id "$CI_SP" --assignee-principal-type ServicePrincipal \
      --role "$role" --scope "$RG_ID" -o none
  fi
done

echo "AZURE_CLIENT_ID=$CI_APP"
echo "AZURE_TENANT_ID=$(az account show --query tenantId -o tsv)"
echo "AZURE_SUBSCRIPTION_ID=$(az account show --query id -o tsv)"
echo "Roles on $RG: $(az role assignment list --assignee "$CI_SP" --scope "$RG_ID" --query '[].roleDefinitionName' -o tsv | paste -sd, -)"
