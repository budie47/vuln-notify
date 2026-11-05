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

# GitHub jobs that use the "production" environment of $REPO may sign in as this app. GitHub sends
# either the classic subject or, for newer repositories, one with immutable owner/repo IDs
# (repo:owner@<id>/name@<id>:...), so trust both. The ID form needs the GitHub CLI (gh) to look up.
add_subject() {  # name subject
  if ! az ad app federated-credential list --id "$CI_APP" --query "[].subject" -o tsv | grep -qx "$2"; then
    az ad app federated-credential create --id "$CI_APP" -o none --parameters "{
      \"name\": \"$1\",
      \"issuer\": \"https://token.actions.githubusercontent.com\",
      \"subject\": \"$2\",
      \"audiences\": [\"api://AzureADTokenExchange\"]
    }"
  fi
}
add_subject github-production "repo:$REPO:environment:production"
if command -v gh >/dev/null && IDS=$(gh api "repos/$REPO" -q '"\(.owner.login)@\(.owner.id)/\(.name)@\(.id)"' 2>/dev/null); then
  add_subject github-production-ids "repo:$IDS:environment:production"
else
  echo "note: gh not available — add the ID-form subject manually if GitHub's login fails (see infra/README.md)" >&2
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
