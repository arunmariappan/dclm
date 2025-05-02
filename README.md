# dclm
Digital Certificate Lifecycle Management SaaS platform 
PostgreSQL 
-------------
superuser
Password - postgres

DATABASE_URL=postgresql://postgres:postgres@localhost:5432/postgres
AZURE_KEY_VAULT_URL=https://dclmcertvault.vault.azure.net/
AZURE_CLIENT_ID=40494ed1-b862-40ff-bf83-d5e709128a61
AZURE_CLIENT_SECRET=m5U8Q~BIBsF49yzGZoOmx2CVC2wQyPd3FILzyae8
AZURE_TENANT_ID=b6b76e47-d4c0-46ca-8f87-8a7874af4d15

Generate Sample PEM Files
----------------------------
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
openssl req -new -x509 -key private.pem -out cert.pem -days 365

Convert PEM to Base64
-------------------------
openssl base64 -in private.pem -out private.b64
openssl base64 -in public.pem -out public.b64
openssl base64 -in cert.pem -out cert.b64


https://www.base64encode.org/