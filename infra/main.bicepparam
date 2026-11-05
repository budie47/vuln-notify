using './main.bicep'

// Non-secret settings: edit here. Secrets and per-deployment values come from environment
// variables, so they never live in the repository (the GitHub workflow sets them from secrets).

param prefix = 'vulnnotify'
param communicationDataLocation = 'Asia Pacific'
param notSeenDays = 90
param minReplicas = 1
param maxReplicas = 2

// Image to deploy; empty on the very first run (see infra/README.md).
param containerImage = readEnvironmentVariable('CONTAINER_IMAGE', '')

param postgresAdminPassword = readEnvironmentVariable('PG_ADMIN_PASSWORD')
param flaskSecretKey = readEnvironmentVariable('FLASK_SECRET_KEY')

// Sign-in (Entra ID). Leave unset to deploy without sign-in.
param authClientId = readEnvironmentVariable('AUTH_CLIENT_ID', '')
param authClientSecret = readEnvironmentVariable('AUTH_CLIENT_SECRET', '')
param requiredGroupId = readEnvironmentVariable('REQUIRED_GROUP_ID', '')

// Email. With Communication Services: SMTP_USER is "<acs name>.<smtp app client id>.<tenant id>"
// and SMTP_PASSWORD is that app's client secret. Or point SMTP_HOST at your own relay.
param smtpHost = readEnvironmentVariable('SMTP_HOST', '')
param smtpUser = readEnvironmentVariable('SMTP_USER', '')
param smtpPassword = readEnvironmentVariable('SMTP_PASSWORD', '')
param smtpAppPrincipalId = readEnvironmentVariable('SMTP_APP_PRINCIPAL_ID', '')
param mailFrom = readEnvironmentVariable('MAIL_FROM', '')
