

# NGX Auth Service

🚀 Authentication & Authorization microservice built with NestJS, JWT, and MongoDB for Ngx Workshop microservices architecture.

## Features

- **User Authentication:** Secure user login and signup using JWT.  
- **Role-Based Access Control (RBAC):** Fine‑grained authorization via NestJS guards and roles.  
- **Token Management:** Generation and validation of access and refresh tokens.  
- **MongoDB Integration:** Reliable storage for users, roles, and permissions.  
- **Modular & Scalable:** Built for easy integration into microservice architectures.  

## Tech Stack

- [NestJS](https://nestjs.com/)  
- [MongoDB](https://www.mongodb.com/) & [Mongoose](https://mongoosejs.com/)  
- [JSON Web Tokens (JWT)](https://jwt.io/)  
- [Docker](https://www.docker.com/) & [Docker Compose](https://docs.docker.com/compose/)  
- [GitHub Actions](https://github.com/features/actions)  

## Prerequisites

- Docker & Docker Compose  
- MongoDB instance  
- Node.js (>=18)  
- NestJS CLI  

## Installation

```bash
git clone https://github.com/ngx-workshop/ngx-auth-service.git
cd ngx-auth-service
npm install
```

## Environment Variables

Create a `.env` file in the project root (see `.env.sample` for reference):

```ini
PORT=3000
JWT_SECRET=your_jwt_secret
MONGODB_URI=your_mongodb_uri
JWT_ISSUER=https://ngx-workshop.io
JWT_AUDIENCE=https://ngx-workshop.io
JWT_ACCESS_TOKEN_TTL=3600
JWT_REFRESH_TOKEN_TTL=86400
```

## Running the App

### Development

```bash
npm run start:dev
```

### Production (Docker)

```bash
docker compose up -d
```

## 📜 API Endpoints

- **POST** `/sign-up`  
  Register a new user

- **POST** `/sign-in`  
  Authenticate existing user

- **GET** `/sign-out`  
  Logout the user

- **GET** `/is-user-logged-in`  
  Check user session status

- **GET** `/user-metadata`  
  Retrieve user profile details

## 🔐 Security

- JWT‑based authentication  
- Environment variables stored securely via GitHub Secrets  
- MongoDB secured by firewall rules and scoped permissions  

## 🤝 Contributing

Contributions are welcome! Please submit a PR or open an issue for bugs or suggestions.

## OAuth engine spike

The [OAuth engine ADR](docs/adr/0001-oauth-engine.md) recommends oidc-provider
9.12.2 with a custom MongoDB adapter. Thirty opt-in cases prove the engine through
real HTTP and isolated MongoDB storage; [results and limits](specs/001-oauth-engine-spike/handoff.md)
include the required replica-set topology for atomic code/token issuance.

Use Node 22 LTS and an installed mongod binary, then run:

```sh
npm run test:oauth:spike
npm run lint:oauth:spike
```

The harness creates/stops its own loopback MongoDB process and temporary data;
it never connects to your existing database or loads live auth credentials.
OAUTH_SPIKE_MONGOD can supply an explicit binary path. The engine is a pinned runtime dependency. Fixture login/consent and metadata
fetch remain test seams; see the local implementation below for real login and
consent. Existing legacy auth and @tmdjr/ngx-auth-client behavior are preserved.

## Local OAuth authorization server

OAuth is now available as an opt-in local module using oidc-provider, real account login/consent and encrypted transaction-backed Mongo storage. Existing cookie auth remains the default. See the [local runbook](docs/oauth-local.md), [implementation spec](specs/002-oauth-implementation/spec.md), and [ADR 0002](docs/adr/0002-local-oauth-implementation.md). Approved CIMD fetching, additive auth-client introspection and gateway bearer
integration are now locally verified; see [integration handoff](specs/003-oauth-integration/handoff.md)
and [ADR 0003](docs/adr/0003-oauth-cimd-introspection.md). Deployment remains deferred.

## Production readiness

Production profiles, persistent secrets, MongoDB checks, hardened containers and
validation-only CI are implemented. See the [readiness runbook](docs/production-readiness.md)
and [deployment handoff](specs/004-deployment/handoff.md). Public infrastructure,
client registrations, recovery proof and rollout remain deferred. Nothing was
deployed or published.
