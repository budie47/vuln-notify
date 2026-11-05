# Deploying Vuln Notify to Azure

`infra/main.bicep` creates everything the app needs in one resource group:

| Resource | Purpose |
|---|---|
| Container Apps environment + Container App | Runs the app image (HTTPS, health probes, 1–2 replicas) |
| PostgreSQL Flexible Server 16 (Burstable B1ms) | Database. **Private only** — reachable from the app's network, not the internet. Daily backups, 7 days |
| Virtual network + private DNS zone | Connects the app to the private database |
| Container Registry (Basic) | Stores the app image |
| Key Vault | Database URL, Flask secret, SMTP password, sign-in secret |
| User-assigned managed identity | Lets the app pull images and read Key Vault, with no passwords |
| Log Analytics workspace | App and platform logs (30 days) |
| Communication Services + Email (Azure-managed domain) | Sends notification emails |
| Container Apps authentication (Entra ID) | Company sign-in in front of the whole app (optional, strongly recommended) |

Two GitHub Actions workflows deploy it:

- **Provision infrastructure** (`.github/workflows/infra.yml`, run manually): applies the Bicep, builds the image, deploys the app. Safe to re-run; use it after changing `infra/` or settings.
- **Deploy app** (`.github/workflows/deploy.yml`, on every push to `main` that touches the app): checks the code, builds the image in the registry, rolls it out, smoke-tests it.

## One-time setup

Replace the values in `<...>`. Run in a shell where `az login` is done with an account that can create
app registrations and assign roles in the subscription.

### 1. Resource group and providers

```bash
az group create -n rg-vuln-notify -l southeastasia
for p in Microsoft.App Microsoft.DBforPostgreSQL Microsoft.Communication Microsoft.ContainerRegistry \
         Microsoft.KeyVault Microsoft.OperationalInsights Microsoft.Network Microsoft.ManagedIdentity; do
  az provider register -n $p
done
```

### 2. Identity for GitHub Actions (OIDC, no stored Azure password)

```bash
SUB=$(az account show --query id -o tsv); TENANT=$(az account show --query tenantId -o tsv)
CI_APP=$(az ad app create --display-name vuln-notify-github --query appId -o tsv)
CI_SP=$(az ad sp create --id $CI_APP --query id -o tsv)

az ad app federated-credential create --id $CI_APP --parameters '{
  "name": "github-production",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:budie47/vuln-notify:environment:production",
  "audiences": ["api://AzureADTokenExchange"]
}'

RG_ID=$(az group show -n rg-vuln-notify --query id -o tsv)
# Contributor to create resources; RBAC Administrator because the template assigns roles
# (registry pull, Key Vault read) to the app's managed identity.
az role assignment create --assignee-object-id $CI_SP --assignee-principal-type ServicePrincipal --role Contributor --scope $RG_ID
az role assignment create --assignee-object-id $CI_SP --assignee-principal-type ServicePrincipal --role "Role Based Access Control Administrator" --scope $RG_ID
echo "AZURE_CLIENT_ID=$CI_APP AZURE_TENANT_ID=$TENANT AZURE_SUBSCRIPTION_ID=$SUB"
```

### 3. App registration for sign-in (recommended)

The app has no login of its own; this puts Entra ID sign-in in front of it. The real redirect URI is
known only after the first deployment, so start with a placeholder and update it in step 6.

```bash
AUTH_APP=$(az ad app create --display-name "Vuln Notify" --sign-in-audience AzureADMyOrg \
  --web-redirect-uris https://placeholder.invalid/.auth/login/aad/callback \
  --enable-id-token-issuance true --query appId -o tsv)
az ad app update --id $AUTH_APP --identifier-uris api://$AUTH_APP
az ad sp create --id $AUTH_APP
AUTH_SECRET=$(az ad app credential reset --id $AUTH_APP --display-name container-apps --years 1 --query password -o tsv)
echo "AUTH_CLIENT_ID=$AUTH_APP"   # AUTH_SECRET goes into a GitHub secret
```

To limit who can sign in: Entra admin center → Enterprise applications → *Vuln Notify* → Properties →
*Assignment required* = Yes, then add users/groups under *Users and groups*.

### 4. GitHub settings

Create an environment named **production** (Settings → Environments; add required reviewers if you
want an approval before each deployment), then set:

```bash
gh secret set AZURE_CLIENT_ID     --env production --body "$CI_APP"
gh secret set AZURE_TENANT_ID     --env production --body "$TENANT"
gh secret set AZURE_SUBSCRIPTION_ID --env production --body "$SUB"
gh secret set PG_ADMIN_PASSWORD   --env production --body "<long random password>"
gh secret set AUTH_CLIENT_SECRET  --env production --body "$AUTH_SECRET"
gh variable set AZURE_RESOURCE_GROUP --body rg-vuln-notify
gh variable set AUTH_CLIENT_ID       --body "$AUTH_APP"
```

`PG_ADMIN_PASSWORD`: 8–128 characters with three of upper case, lower case, digits and symbols. Keep
it unchanged afterwards — every run sets the server's admin password to this value.

### 5. First deployment

GitHub → Actions → **Provision infrastructure** → *Run workflow*. It takes about 10–15 minutes the
first time (the database is the slow part). The run summary shows `appUrl`, `signInRedirectUri`,
`mailFrom` and `smtpUsernameHint`.

### 6. Point sign-in at the real address

```bash
az ad app update --id $AUTH_APP --web-redirect-uris "<signInRedirectUri from the run summary>"
```

Open `appUrl`: you should get the Microsoft sign-in page, then the dashboard with your name top right.

### 7. Email

Communication Services sends from `mailFrom` (e.g. `DoNotReply@xxxx.azurecomm.net`). SMTP login uses
an Entra app:

```bash
SMTP_APP=$(az ad app create --display-name vuln-notify-smtp --query appId -o tsv)
SMTP_SP=$(az ad sp create --id $SMTP_APP --query id -o tsv)
SMTP_SECRET=$(az ad app credential reset --id $SMTP_APP --display-name smtp --years 1 --query password -o tsv)

gh variable set SMTP_APP_PRINCIPAL_ID --body "$SMTP_SP"
gh variable set SMTP_USER --body "<smtpUsernameHint with <smtp app client id> replaced by $SMTP_APP>"
gh secret set SMTP_PASSWORD --env production --body "$SMTP_SECRET"
```

Run **Provision infrastructure** again. It grants that app access to Communication Services and
gives the app the SMTP settings. Then use *Send notification* on an app to test.

Using your company's SMTP relay instead: set `SMTP_HOST`, `SMTP_USER`, `MAIL_FROM` (variables) and
`SMTP_PASSWORD` (secret), and set `deployCommunicationServices = false` in `infra/main.bicepparam`.

## Day to day

- **Code changes:** merge to `main` → *Deploy app* runs automatically.
- **Settings or infrastructure changes:** edit `infra/main.bicepparam` / `infra/main.bicep`, merge, run *Provision infrastructure*.
- **Logs:** Azure portal → the Container App → *Log stream*, or *Logs* (Log Analytics):
  `ContainerAppConsoleLogs_CL | where ContainerAppName_s == "vulnnotify-app" | order by TimeGenerated desc`
- **Database access** (private): use the portal's *Connect* blade from a machine in the VNet, or temporarily allow your IP.

## Notes

- Container Apps ends a web request after ~4 minutes. Finalizing an import of a few thousand rows takes seconds; tens of thousands could get close. If exports grow that large, move Finalize into a background job.
- Rough cost at the default sizes: PostgreSQL B1ms ≈ US$15–30/month, Container App ≈ US$5–20, Container Registry Basic ≈ US$5, Log Analytics a few dollars, email cents per thousand. Check the Azure pricing calculator for your region.
- Re-running *Provision infrastructure* rotates the Flask secret key (signed-in users only lose pending flash messages).
