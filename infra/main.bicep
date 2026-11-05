// Vuln Notify on Azure: Container Apps + PostgreSQL Flexible Server (private) + Key Vault + ACR
// + Log Analytics + Communication Services Email, with optional Entra ID sign-in.
//
// Deployed into an existing resource group:
//   az deployment group create -g <rg> -f infra/main.bicep -p infra/main.bicepparam
// See infra/README.md for the one-time setup and the GitHub Actions workflows.

targetScope = 'resourceGroup'

@description('Azure region for all regional resources.')
param location string = resourceGroup().location

@description('Short prefix used in resource names (lowercase letters and digits).')
@minLength(3)
@maxLength(12)
param prefix string = 'vulnnotify'

@description('Container image to run, e.g. myacr.azurecr.io/vuln-notify:<sha>. Leave empty on the very first deployment: everything except the Container App is created, so the image can be built into the new registry first.')
param containerImage string = ''

// ---- database
@description('PostgreSQL administrator login.')
param postgresAdminLogin string = 'vnadmin'

@description('PostgreSQL administrator password.')
@secure()
param postgresAdminPassword string

@description('PostgreSQL compute SKU. Burstable B1ms is enough for a small internal tool.')
param postgresSkuName string = 'Standard_B1ms'

@allowed(['Burstable', 'GeneralPurpose', 'MemoryOptimized'])
param postgresSkuTier string = 'Burstable'

param postgresStorageGb int = 32
param postgresBackupRetentionDays int = 7

// ---- app settings
@description('Open alerts with no newer scan of their asset for this many days are flagged "Not seen".')
param notSeenDays int = 90

@description('Flask secret key. Signs session data and encrypts the SMTP password saved on the Settings page, so keep it the same across deployments.')
@secure()
@minLength(32)
param flaskSecretKey string

@minValue(0)
param minReplicas int = 1
param maxReplicas int = 2

// ---- email
@description('Create Azure Communication Services Email with an Azure-managed sender domain. Set false to use your own SMTP relay (smtpHost etc.).')
param deployCommunicationServices bool = true

@description('Data location for Communication Services, e.g. "Asia Pacific", "Europe", "United States".')
param communicationDataLocation string = 'Asia Pacific'

@description('SMTP host. Leave empty to use Communication Services (smtp.azurecomm.net).')
param smtpHost string = ''
param smtpPort int = 587

@description('SMTP username. For Communication Services: "<acs name>.<smtp app client id>.<tenant id>" — see the smtpUsernameHint output.')
param smtpUser string = ''

@description('SMTP password. For Communication Services: the client secret of the Entra app used for SMTP.')
@secure()
param smtpPassword string = ''

@description('Sender address. Leave empty to use DoNotReply@<Azure-managed domain> from Communication Services.')
param mailFrom string = ''

@description('Object ID of the service principal (enterprise app) used for SMTP with Communication Services. When set, it is granted access to the Communication Services resource.')
param smtpAppPrincipalId string = ''

// ---- sign-in (Entra ID via Container Apps authentication)
@description('Object ID of the Entra security group whose members may use the app. Requires sign-in (authClientId) and the app registration to emit group claims. Empty = any signed-in user of the tenant.')
param requiredGroupId string = ''

@description('Display name of that group, shown on the access-denied page.')
param requiredGroupName string = 'vn_admin'

@description('Client (application) ID of the Entra app registration for user sign-in. Leave empty to deploy without sign-in (NOT recommended: the app has no login of its own).')
param authClientId string = ''

@description('Client secret of that Entra app registration.')
@secure()
param authClientSecret string = ''

param tags object = {
  app: 'vuln-notify'
}

// ---------------------------------------------------------------- names
var suffix = uniqueString(resourceGroup().id)
var names = {
  logs: '${prefix}-logs'
  identity: '${prefix}-id'
  acr: take('${prefix}acr${suffix}', 50)
  keyVault: take('${prefix}-kv-${suffix}', 24)
  vnet: '${prefix}-vnet'
  postgres: '${prefix}-pg-${suffix}'
  env: '${prefix}-env'
  app: '${prefix}-app'
  emailService: '${prefix}-email-${suffix}'
  acs: '${prefix}-acs-${suffix}'
}
var databaseName = 'vulnnotify'
var authEnabled = !empty(authClientId)

// Built-in role definition IDs
var roles = {
  acrPull: '7f951dda-4ed3-4680-a7ca-43fe172d538d'
  keyVaultSecretsUser: '4633458b-17de-408a-b874-0445c86b69e6'
  contributor: 'b24988ac-6180-42a0-ab88-20f7382dd24c'
}

// ---------------------------------------------------------------- monitoring
resource logs 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: names.logs
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

// ---------------------------------------------------------------- identity used by the app
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: names.identity
  location: location
  tags: tags
}

// ---------------------------------------------------------------- container registry
resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: names.acr
  location: location
  tags: tags
  sku: { name: 'Basic' }
  properties: {
    adminUserEnabled: false
  }
}

resource acrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, identity.id, roles.acrPull)
  scope: acr
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.acrPull)
  }
}

// ---------------------------------------------------------------- network
resource vnet 'Microsoft.Network/virtualNetworks@2023-09-01' = {
  name: names.vnet
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: ['10.40.0.0/16'] }
    subnets: [
      {
        name: 'snet-apps'
        properties: {
          addressPrefix: '10.40.0.0/23'
          delegations: [
            { name: 'apps', properties: { serviceName: 'Microsoft.App/environments' } }
          ]
        }
      }
      {
        name: 'snet-postgres'
        properties: {
          addressPrefix: '10.40.2.0/24'
          delegations: [
            { name: 'postgres', properties: { serviceName: 'Microsoft.DBforPostgreSQL/flexibleServers' } }
          ]
        }
      }
    ]
  }
}

// Private DNS so the app resolves the database to its private address.
resource postgresDns 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: '${names.postgres}.private.postgres.database.azure.com'
  location: 'global'
  tags: tags
}

resource postgresDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: postgresDns
  name: '${names.vnet}-link'
  location: 'global'
  properties: {
    virtualNetwork: { id: vnet.id }
    registrationEnabled: false
  }
}

// ---------------------------------------------------------------- database (private, no public access)
resource postgres 'Microsoft.DBforPostgreSQL/flexibleServers@2024-08-01' = {
  name: names.postgres
  location: location
  tags: tags
  sku: {
    name: postgresSkuName
    tier: postgresSkuTier
  }
  properties: {
    version: '16'
    administratorLogin: postgresAdminLogin
    administratorLoginPassword: postgresAdminPassword
    storage: { storageSizeGB: postgresStorageGb, autoGrow: 'Enabled' }
    backup: { backupRetentionDays: postgresBackupRetentionDays, geoRedundantBackup: 'Disabled' }
    highAvailability: { mode: 'Disabled' }
    network: {
      delegatedSubnetResourceId: '${vnet.id}/subnets/snet-postgres'
      privateDnsZoneArmResourceId: postgresDns.id
      publicNetworkAccess: 'Disabled'
    }
  }
  dependsOn: [postgresDnsLink]
}

resource database 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2024-08-01' = {
  parent: postgres
  name: databaseName
  properties: {
    charset: 'UTF8'
    collation: 'en_US.utf8'
  }
}

// ---------------------------------------------------------------- email (Communication Services)
resource emailService 'Microsoft.Communication/emailServices@2023-04-01' = if (deployCommunicationServices) {
  name: names.emailService
  location: 'global'
  tags: tags
  properties: { dataLocation: communicationDataLocation }
}

resource emailDomain 'Microsoft.Communication/emailServices/domains@2023-04-01' = if (deployCommunicationServices) {
  parent: emailService
  name: 'AzureManagedDomain'
  location: 'global'
  tags: tags
  properties: {
    domainManagement: 'AzureManaged'
    userEngagementTracking: 'Disabled'
  }
}

resource acs 'Microsoft.Communication/communicationServices@2023-04-01' = if (deployCommunicationServices) {
  name: names.acs
  location: 'global'
  tags: tags
  properties: {
    dataLocation: communicationDataLocation
    linkedDomains: [emailDomain.id]
  }
}

// The Entra app used as the SMTP login needs access to the Communication Services resource.
resource smtpAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployCommunicationServices && !empty(smtpAppPrincipalId)) {
  name: guid(names.acs, smtpAppPrincipalId, roles.contributor)
  scope: acs
  properties: {
    principalId: smtpAppPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.contributor)
  }
}

var effectiveSmtpHost = !empty(smtpHost) ? smtpHost : (deployCommunicationServices ? 'smtp.azurecomm.net' : '')
var effectiveMailFrom = !empty(mailFrom)
  ? mailFrom
  : (deployCommunicationServices ? 'DoNotReply@${emailDomain!.properties.mailFromSenderDomain}' : 'vuln-notify@example.com')

// ---------------------------------------------------------------- secrets
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: names.keyVault
  location: location
  tags: tags
  properties: {
    tenantId: tenant().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
  }
}

resource kvSecretsUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, identity.id, roles.keyVaultSecretsUser)
  scope: keyVault
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.keyVaultSecretsUser)
  }
}

var databaseUrl = 'postgresql+psycopg2://${postgresAdminLogin}:${uriComponent(postgresAdminPassword)}@${postgres.properties.fullyQualifiedDomainName}:5432/${databaseName}?sslmode=require'

resource secretDatabaseUrl 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'database-url'
  properties: { value: databaseUrl }
}

resource secretFlaskKey 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'flask-secret-key'
  properties: { value: flaskSecretKey }
}

resource secretSmtpPassword 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'smtp-password'
  // Key Vault does not accept an empty value; the app ignores the password when no SMTP user is set.
  properties: { value: empty(smtpPassword) ? 'not-set' : smtpPassword }
}

resource secretAuthClient 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (authEnabled) {
  parent: keyVault
  name: 'auth-client-secret'
  properties: { value: authClientSecret }
}

// ---------------------------------------------------------------- container apps
resource appsEnv 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: names.env
  location: location
  tags: tags
  properties: {
    workloadProfiles: [
      { name: 'Consumption', workloadProfileType: 'Consumption' }
    ]
    vnetConfiguration: {
      infrastructureSubnetId: '${vnet.id}/subnets/snet-apps'
      internal: false
    }
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logs.properties.customerId
        sharedKey: logs.listKeys().primarySharedKey
      }
    }
  }
}

var kvSecretRefs = concat(
  [
    { name: 'database-url', keyVaultUrl: secretDatabaseUrl.properties.secretUri, identity: identity.id }
    { name: 'flask-secret-key', keyVaultUrl: secretFlaskKey.properties.secretUri, identity: identity.id }
    { name: 'smtp-password', keyVaultUrl: secretSmtpPassword.properties.secretUri, identity: identity.id }
  ],
  authEnabled
    ? [{ name: 'microsoft-provider-authentication-secret', keyVaultUrl: secretAuthClient!.properties.secretUri, identity: identity.id }]
    : []
)

resource app 'Microsoft.App/containerApps@2024-03-01' = if (!empty(containerImage)) {
  name: names.app
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${identity.id}': {} }
  }
  properties: {
    environmentId: appsEnv.id
    workloadProfileName: 'Consumption'
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 5000
        transport: 'auto'
        allowInsecure: false
      }
      registries: [
        { server: acr.properties.loginServer, identity: identity.id }
      ]
      secrets: kvSecretRefs
    }
    template: {
      containers: [
        {
          name: 'app'
          image: containerImage
          resources: { cpu: json('0.5'), memory: '1Gi' }
          env: [
            { name: 'DATABASE_URL', secretRef: 'database-url' }
            { name: 'SECRET_KEY', secretRef: 'flask-secret-key' }
            { name: 'TRUST_PROXY', value: 'true' }
            { name: 'NOT_SEEN_DAYS', value: string(notSeenDays) }
            { name: 'SMTP_HOST', value: effectiveSmtpHost }
            { name: 'SMTP_PORT', value: string(smtpPort) }
            { name: 'SMTP_SECURITY', value: 'starttls' }
            { name: 'REQUIRED_GROUP_ID', value: requiredGroupId }
            { name: 'REQUIRED_GROUP_NAME', value: requiredGroupName }
            { name: 'SMTP_USER', value: smtpUser }
            { name: 'SMTP_PASSWORD', secretRef: 'smtp-password' }
            { name: 'MAIL_FROM', value: effectiveMailFrom }
          ]
          probes: [
            {
              type: 'Startup'
              httpGet: { path: '/healthz', port: 5000 }
              initialDelaySeconds: 5
              periodSeconds: 5
              failureThreshold: 24
            }
            {
              type: 'Liveness'
              httpGet: { path: '/healthz', port: 5000 }
              periodSeconds: 30
              failureThreshold: 3
            }
            {
              type: 'Readiness'
              httpGet: { path: '/healthz', port: 5000 }
              periodSeconds: 15
              failureThreshold: 3
            }
          ]
        }
      ]
      scale: {
        minReplicas: minReplicas
        maxReplicas: maxReplicas
        rules: [
          { name: 'http', http: { metadata: { concurrentRequests: '30' } } }
        ]
      }
    }
  }
  dependsOn: [acrPull, kvSecretsUser, database]
}

// Entra ID sign-in in front of the whole app (Container Apps built-in authentication).
resource auth 'Microsoft.App/containerApps/authConfigs@2024-03-01' = if (!empty(containerImage) && authEnabled) {
  parent: app
  name: 'current'
  properties: {
    platform: { enabled: true }
    globalValidation: {
      unauthenticatedClientAction: 'RedirectToLoginPage'
      redirectToProvider: 'azureactivedirectory'
    }
    identityProviders: {
      azureActiveDirectory: {
        enabled: true
        registration: {
          clientId: authClientId
          clientSecretSettingName: 'microsoft-provider-authentication-secret'
          openIdIssuer: '${environment().authentication.loginEndpoint}${tenant().tenantId}/v2.0'
        }
        validation: {
          allowedAudiences: ['api://${authClientId}']
        }
      }
    }
    login: {
      preserveUrlFragmentsForLogins: true
    }
  }
}

// ---------------------------------------------------------------- outputs
output acrName string = acr.name
output acrLoginServer string = acr.properties.loginServer
output containerAppName string = names.app
output appUrl string = !empty(containerImage) ? 'https://${app!.properties.configuration.ingress.fqdn}' : ''
output authRedirectUri string = !empty(containerImage) ? 'https://${app!.properties.configuration.ingress.fqdn}/.auth/login/aad/callback' : ''
output postgresServer string = postgres.properties.fullyQualifiedDomainName
output keyVaultName string = keyVault.name
output mailFrom string = effectiveMailFrom
output smtpUsernameHint string = deployCommunicationServices ? '${names.acs}.<smtp app client id>.${tenant().tenantId}' : ''
