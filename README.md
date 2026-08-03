# User Management Service

## 1. Introduction
This service provides user management APIs for UPCAST. It owns user CRUD and the MongoDB user profile records.
In the Keycloak architecture it also creates the Keycloak user during registration, stores the returned `keycloak_sub` in MongoDB, and keeps password/delete operations aligned with Keycloak.

## 2. How to run locally with docker-compose
1. Ensure `.env` exists in this folder and includes at least:
   - `MONGO_USER`
   - `MONGO_PASSWORD`
   - `MONGO_HOST`
   - `MONGO_PORT`
   - `MASTER_PASSWORD`
   - `KEYCLOAK_BASE_URL`
   - `KEYCLOAK_REALM`
   - `KEYCLOAK_ADMIN_USERNAME`
   - `KEYCLOAK_ADMIN_PASSWORD`

2. Build and start:
```bash
docker compose up --build
```

3. The API listens on:
```text
http://localhost:8800
```

## 3. Available APIs
- `POST /user/register`
- `PUT /user/update-details`
- `PUT /user/update-password`
- `GET /user/details/`
- `GET /user/check_user_email/`
- `DELETE /user/delete/{user_id}`
- `GET /health`

## 4. Registration flow
1. GUI calls `POST /user/register`
2. service validates master password and user payload
3. service creates the Keycloak user first
4. service stores the MongoDB profile with:
   - `keycloak_sub`
   - `first_name`
   - `last_name`
   - `name`
   - `email`
   - other application-specific fields
5. if MongoDB insert fails, the created Keycloak user is rolled back

## 5. Example curl commands
Register a user:
```bash
curl -X POST "http://localhost:8800/user/register?master_password_input=master_password"   -H "Content-Type: application/json"   -d '{
    "first_name": "Data",
    "last_name": "Consumer",
    "email": "user@example.com",
    "password": "StrongPass1!",
    "type": "consumer",
    "organization": "ACME"
    ...
  }'
```

Get a user's details directly:
```bash
curl -X GET "http://localhost:8800/user/details/?user_id=<user_id>"
```

Get a user's details by email:
```bash
curl -X GET "http://localhost:8800/user/details/?user_email=datapack_consumer3@example.com"
```

Get a user's details by Keycloak user id:
```bash
curl -X GET "http://localhost:8800/user/details/?keycloak_sub=<keycloak_user_id>"
```

Check whether a user email exists:
```bash
curl -X GET "http://localhost:8800/user/check_user_email/?user_email=datapack_consumer3@example.com"
```

Update a user's details directly by id or email:
```bash
curl -X PUT "http://localhost:8800/user/update-details?user_id=<user_id>" \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "Updated",
    "last_name": "User",
    "organization": ["ACME", "EU Division"],
    "phone": "+44-000-000-000"
  }'
```

