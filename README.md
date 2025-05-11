# dclm
Digital Certificate Lifecycle Management SaaS platform 
PostgreSQL 
-------------
superuser
Password - postgres

Client Az - P@$$4ns#

Local
------
{
    "tenant_id": "b6b76e47-d4c0-46ca-8f87-8a7874af4d15",
    "client_id": "40494ed1-b862-40ff-bf83-d5e709128a61",
    "client_secret": "",
    "vault_url": "https://dclmcertvault.vault.azure.net/",
    "database_url": "postgresql://postgres:postgres@localhost:5432/postgres"
}

-- Self
AZURE_CLIENT_ID=40494ed1-b862-40ff-bf83-d5e709128a61
AZURE_CLIENT_SECRET=m5U8Q~BIBsF49yzGZoOmx2CVC2wQyPd3FILzyae8
AZURE_TENANT_ID=b6b76e47-d4c0-46ca-8f87-8a7874af4d15
KEY_VAULT_URL=https://dclmcertvault.vault.azure.net/
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/postgres

Client
AZURE_CLIENT_ID=5ff46d24-a31a-4d30-aaeb-f4715cf5e58d
AZURE_CLIENT_SECRET=7NM8Q~v2TAJWyj9_cQXCJUpsxHYFTzr5R0NBqa~F
AZURE_TENANT_ID=4419d016-6ca7-4bea-867b-c8f57e97f397
KEY_VAULT_URL=https://azure-key-vault-maple.vault.azure.net/
DATABASE_URL=postgresql://sjhdgfyesdgdewasa:eredsdSawsd53!ewrty$@server-dev.postgres.database.azure.com:5432/postgres

Generate Sample PEM Files
----------------------------
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

Convert PEM to Base64
-------------------------
openssl base64 -in private.pem -out private.b64
# Remove newlines for JSON compatibility
tr -d '\n' < private.b64 > private_key_oneline.b64

openssl base64 -in public.pem -out public.b64
# Remove newlines for JSON compatibility
tr -d '\n' < public.b64 > public_key_oneline.b64

https://www.i2text.com/remove-line-breaks

--- Azure Me
az login --service-principal --username 40494ed1-b862-40ff-bf83-d5e709128a61 --password m5U8Q~BIBsF49yzGZoOmx2CVC2wQyPd3FILzyae8 --tenant b6b76e47-d4c0-46ca-8f87-8a7874af4d15

az keyvault secret set --vault-name dclmcertvault --name test-secret --value "test-value"

-- Azure client
az login --service-principal --username 5ff46d24-a31a-4d30-aaeb-f4715cf5e58d --password TekAdmin --tenant 4419d016-6ca7-4bea-867b-c8f57e97f397

curl -X POST \
  -d "grant_type=client_credentials" \
  -d "client_id=5ff46d24-a31a-4d30-aaeb-f4715cf5e58d" \
  -d "client_secret=TekAdmin" \
  -d "scope=https://azure-key-vault-maple.vault.azure.net/" \
  "https://login.microsoftonline.com/4419d016-6ca7-4bea-867b-c8f57e97f397/oauth2/v2.0/token"

-----------------------------------------------------
Copilot
-----------------------------------------------------

openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:4096
openssl rsa -pubout -in private_key.pem -out public_key.pem

base64 private_key.pem > private_key_base64.txt
base64 public_key.pem > public_key_base64.txt
------------------------------------------------------------------------------------------
------ Generate private key
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:4096
openssl rsa -pubout -in private_key.pem -out public_key.pem

-- Certificate
openssl req -new -key private_key.pem -out certificate.csr -subj "/C=IN/ST=Karnataka/L=Bengaluru/O=Maple Solutions/CN=maple-solutions.com"
-- Self signed certificate
openssl x509 -req -days 365 -in certificate.csr -signkey private_key.pem -out certificate.pem
-- convert certificate to pfx
openssl pkcs12 -export -out certificate.pfx -inkey private_key.pem -in certificate.pem -name "maple-solutions" -password pass:123456

-- base64
base64 -w 0 private_key.pem > private_key_base64.txt
base64 -w 0 public_key.pem > public_key_base64.txt
base64 -w 0 certificate.pem > certificate_base64.txt
base64 certificate.pfx > certificate_pfx_base64.txt

------------------------------------------------
Grok
------------------------------------------------
Generate Test Keys:

openssl genrsa -out private.key 2048
openssl req -new -x509 -key private.key -out certificate.crt -days 365
openssl rsa -in private.key -pubout -out public.key

base64 private.key > private.b64
base64 certificate.crt > cert.b64
base64 public.key > public.b64