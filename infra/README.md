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
| `vn_admin` security group (created by the setup steps) | Only members can use the app — checked by the app from the sign-in's group claim (works on Entra ID Free) |

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
bash infra/setup-github-identity.sh rg-vuln-notify budie47/vuln-notify
```

Creates the `vuln-notify-github` app registration with a federated credential for this repository's
`production` environment, and gives it **Contributor** and **Role Based Access Control Administrator**
on the resource group (the template assigns roles to the app's managed identity). It prints
`AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_SUBSCRIPTION_ID` for step 4.

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

Only members of a security group may use the app. Entra ID Free cannot restrict an app to a group,
so the app registration emits group claims and the app checks them (users outside the group see
*Access denied*):

```bash
GROUP_ID=$(az ad group create --display-name vn_admin --mail-nickname vn_admin \
  --description "Users allowed to use Vuln Notify" --query id -o tsv)
az ad app update --id $AUTH_APP --set groupMembershipClaims=SecurityGroup
az ad group member add --group vn_admin --member-id $(az ad signed-in-user show --query id -o tsv)
```

Add or remove people with Entra admin center → Groups → *vn_admin* → Members. Changes apply at their
next sign-in.

### 4. GitHub settings

Create an environment named **production** (Settings → Environments; add required reviewers if you
want an approval before each deployment), then set:

```bash
gh secret set AZURE_CLIENT_ID     --env production --body "<AZURE_CLIENT_ID from step 2>"
gh secret set AZURE_TENANT_ID     --env production --body "<AZURE_TENANT_ID from step 2>"
gh secret set AZURE_SUBSCRIPTION_ID --env production --body "<AZURE_SUBSCRIPTION_ID from step 2>"
gh secret set PG_ADMIN_PASSWORD   --env production --body "<long random password>"
gh secret set FLASK_SECRET_KEY    --env production --body "$(openssl rand -hex 32)"   # keep it: encrypts saved SMTP password
gh secret set AUTH_CLIENT_SECRET  --env production --body "$AUTH_SECRET"
gh variable set AZURE_RESOURCE_GROUP --body rg-vuln-notify
gh variable set AUTH_CLIENT_ID       --body "$AUTH_APP"
gh variable set REQUIRED_GROUP_ID    --body "$GROUP_ID"
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

Switching to your company's SMTP relay later: open **Settings** in the app, enter the relay's
server, port, security, login and sender, *Save*, then *Send test email*. No redeployment needed;
saved settings take precedence over the deployment defaults.

## Day to day

- **Code changes:** merge to `main` → *Deploy app* runs automatically.
- **Settings or infrastructure changes:** edit `infra/main.bicepparam` / `infra/main.bicep`, merge, run *Provision infrastructure*.
- **Logs:** Azure portal → the Container App → *Log stream*, or *Logs* (Log Analytics):
  `ContainerAppConsoleLogs_CL | where ContainerAppName_s == "vulnnotify-app" | order by TimeGenerated desc`
- **Database access** (private): use the portal's *Connect* blade from a machine in the VNet, or temporarily allow your IP.

## Notes

- Container Apps ends a web request after ~4 minutes. Finalizing an import of a few thousand rows takes seconds; tens of thousands could get close. If exports grow that large, move Finalize into a background job.
- Rough cost at the default sizes: PostgreSQL B1ms ≈ US$15–30/month, Container App ≈ US$5–20, Container Registry Basic ≈ US$5, Log Analytics a few dollars, email cents per thousand. Check the Azure pricing calculator for your region.
- Keep `FLASK_SECRET_KEY` unchanged: it encrypts the SMTP password saved on the Settings page. If it changes, the page asks for the password again.
