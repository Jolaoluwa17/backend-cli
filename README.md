# express-backend-scaffold (Backend CLI)

A tiny CLI that scaffolds a **TypeScript + Express + MongoDB** backend starter.

- **Package name**: `express-backend-scaffold`
- **CLI command**: `backend-cli`
- **Node**: >= 14

## Installation

```bash
npm install -g express-backend-scaffold
```

## Usage

```bash
backend-cli [project-name]
```

- If `project-name` is omitted, it defaults to `backend-project`.
- If the target directory already exists **and is not empty**, the CLI exits with an error (to avoid overwriting files).
- The CLI will prompt you to optionally include:
  - **Authentication system** (signup/login with JWT, User model, auth middleware)
  - **Role-based access control** (RBAC with verifyRoles middleware - requires auth)
  - **Swagger API documentation** (OpenAPI 3.0 with `/api-docs` endpoint)
  - **Docker configuration** (Dockerfile, docker-compose.yml)
  - **Rate limiting** (with customizable limits for API and auth endpoints)
  - **CI/CD templates** (GitHub Actions & GitLab CI)
  - **Jest testing setup** (with example tests)
  - **Health check endpoint** (`/health` route)

### Example

```bash
backend-cli my-backend-api
```

You'll be prompted with interactive questions:
```
? Would you like to include authentication system (signup/login with JWT)? (Y/n)
? Would you like to include Swagger API documentation? (Y/n)
? Would you like to include Docker configuration files? (Y/n)
? Would you like to include rate limiting? (Y/n)
? Use default rate limiting settings? (Y/n)
  (If no, you'll be asked to customize API and auth rate limits)
? Would you like to include CI/CD templates (GitHub Actions & GitLab CI)? (y/N)
? Would you like to include Jest testing setup? (y/N)
? Would you like to include a health check endpoint (/health)? (Y/n)
```

## Generated project structure

```bash
my-backend-api/
├── config/
│   ├── allowedOrigins.ts
│   ├── corsOptions.ts
│   ├── roles_list.ts
│   └── swagger.ts
├── controllers/
│   └── authController.ts
├── emails/
├── middleware/
│   └── verifyJWT.ts
├── migrations/
│   └── index.ts
├── models/
│   └── User.ts
├── routes/
│   ├── auth.ts
│   └── main.ts
├── scripts/
├── services/
├── utils/
├── .dockerignore
├── .env
├── .env.example
├── .gitignore
├── .prettierrc
├── docker-compose.dev.yml
├── docker-compose.yml
├── Dockerfile
├── Dockerfile.dev
├── package.json
├── server.ts
└── tsconfig.json
```

## Next steps (after generating)

```bash
cd my-backend-api
npm install
```

Update `.env`:

- **`DB_URL`**: MongoDB connection string (local or Atlas)
- **`ACCESS_TOKEN_SECRET`**: JWT signing secret
- **`ACCESS_PORT`**: server port (defaults to `5500`)

Generate a good secret:

```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

Run the server:

```bash
npm run dev
```

## What you get

- **Express server**: `server.ts` (CORS, JSON parsing, cookies, starter route wiring)
- **Mongo connection**: `migrations/index.ts` (reads `DB_URL` from `.env`)
- **CORS config**: `config/allowedOrigins.ts` + `config/corsOptions.ts`
- **Swagger documentation**: `config/swagger.ts` + `/api-docs` endpoint (OpenAPI 3.0)
- **Authentication flow**: Complete user auth with signup/login endpoints
  - User model (`models/User.ts`) with email, password, fullName, and roles
  - Auth controller (`controllers/authController.ts`) with signup & login
  - Auth routes (`routes/auth.ts`) mounted at `/api/v1/auth`
  - JWT middleware (`middleware/verifyJWT.ts`) for protecting routes
  - Role-based access control (`middleware/verifyRoles.ts`) for role verification
- **Error handling**: Centralized error handling middleware (`middleware/errorHandler.ts`)
- **Rate limiting**: API protection (`middleware/rateLimiter.ts`)
  - General API: 100 requests per 15 minutes
  - Auth endpoints: 5 requests per 15 minutes
- **Utilities**: Helper functions for validation, pagination, and environment checks
- **Health check**: `/health` endpoint for monitoring
- **API versioning**: All routes under `/api/v1`
- **Route entrypoint**: `routes/main.ts` (includes auth routes)

### Swagger API Documentation

After starting the server, visit `http://localhost:5500/api-docs` to view interactive API documentation. The Swagger configuration automatically scans your route files for JSDoc comments.

Example route documentation:
```typescript
/**
 * @swagger
 * /api/users:
 *   get:
 *     summary: Get all users
 *     tags: [Users]
 *     responses:
 *       200:
 *         description: List of users
 */
```

### Authentication

The generated project includes a complete authentication system:

**Endpoints:**
- `POST /api/v1/auth/signup` - Register a new user
- `POST /api/v1/auth/login` - Login user
- `GET /health` - Health check endpoint

**Example signup request:**
```bash
curl -X POST http://localhost:5500/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123",
    "fullName": "John Doe"
  }'
```

**Example login request:**
```bash
curl -X POST http://localhost:5500/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'
```

**Health check:**
```bash
curl http://localhost:5500/health
```

**Protecting routes with JWT:**
```typescript
import { verifyJWT } from '../middleware/verifyJWT';
import { AuthRequest } from '../middleware/verifyJWT';

router.get('/protected', verifyJWT, (req: AuthRequest, res: Response) => {
  // req.userId and req.roles are available here
  res.json({ userId: req.userId, roles: req.roles });
});
```

**Protecting routes with role-based access:**
```typescript
import { verifyJWT } from '../middleware/verifyJWT';
import { verifyRoles } from '../middleware/verifyRoles';

// Allow only Admin and SuperAdmin
router.get('/admin-only', verifyJWT, verifyRoles(['Admin', 'SuperAdmin']), (req, res) => {
  res.json({ message: 'Admin access granted' });
});

// Allow only SuperAdmin
router.delete('/super-admin-only', verifyJWT, verifyRoles(['SuperAdmin']), (req, res) => {
  res.json({ message: 'SuperAdmin access granted' });
});
```

**Available roles:**
- `TeamMember` (default role for new users)
- `Admin`
- `SuperAdmin`

**Using the token:**
Include the token in the Authorization header:
```
Authorization: Bearer <your-access-token>
```

### Error Handling

The project includes centralized error handling:

```typescript
import { AppError } from '../middleware/errorHandler';

// Throw custom errors in controllers
throw new AppError('User not found', 404);

// Error handler middleware automatically catches and formats errors
```

### Rate Limiting

Rate limiting is automatically applied:
- **General API routes**: 100 requests per 15 minutes per IP
- **Auth routes**: 5 requests per 15 minutes per IP

### Pagination Utilities

Use pagination helpers for list endpoints:

```typescript
import { getPaginationOptions, createPaginationResult } from '../utils/pagination';

const { page, limit, sort, order } = getPaginationOptions(req.query);
const users = await User.find().skip((page - 1) * limit).limit(limit);
const total = await User.countDocuments();

res.json(createPaginationResult(users, total, page, limit));
```

### Validation Utilities

Use validation helpers:

```typescript
import { isValidEmail, validateRequired, sanitizeString } from '../utils/validation';

// Validate email
if (!isValidEmail(email)) {
  throw new AppError('Invalid email format', 400);
}

// Check required fields
const { isValid, missingFields } = validateRequired(req.body, ['email', 'password']);
if (!isValid) {
  throw new AppError(\`Missing fields: \${missingFields.join(', ')}\`, 400);
}
```

## Optional Features

### Authentication System

If you selected authentication during project creation, you'll get:

- **User model** (`models/User.ts`) - Email, password, fullName (roles included if RBAC is enabled)
- **Auth controller** (`controllers/authController.ts`) - Signup & login endpoints
- **Auth routes** (`routes/auth.ts`) - `/api/v1/auth/signup` and `/api/v1/auth/login`
- **JWT middleware** (`middleware/verifyJWT.ts`) - Token verification

**Note:** If auth is not included, `ACCESS_TOKEN_SECRET` is not required in `.env`. Role management is a separate optional feature.

### Role-Based Access Control (RBAC)

If you selected role management during project creation (requires auth), you'll get:

- **Role management** (`config/roles_list.ts`) - Role definitions (TeamMember, Admin, SuperAdmin)
- **verifyRoles middleware** (`middleware/verifyRoles.ts`) - Role verification middleware
- **User roles** - Roles field added to User model
- **Role-based JWT** - Roles included in JWT tokens

**Usage:**
```typescript
import { verifyJWT } from '../middleware/verifyJWT';
import { verifyRoles } from '../middleware/verifyRoles';

// Protect route with specific roles
router.get('/admin-only', verifyJWT, verifyRoles(['Admin', 'SuperAdmin']), handler);
```

**Note:** Role management requires authentication to be enabled. If you enable auth but not role management, you'll only get `verifyJWT` middleware without roles.

### Swagger API Documentation

If you selected Swagger during project creation, you'll get:

- **Swagger config** (`config/swagger.ts`) - OpenAPI 3.0 configuration
- **Interactive docs** - Available at `/api-docs` endpoint
- **Auto-generated** - Scans route files for JSDoc comments

### Docker Support

If you selected Docker during project creation, you'll get:

- **Dockerfile** - Production build configuration
- **Dockerfile.dev** - Development with hot reload
- **docker-compose.yml** - Production setup (backend + MongoDB)
- **docker-compose.dev.yml** - Development setup
- **.dockerignore** - Excludes unnecessary files
- **Docker scripts** in `package.json`:
  - `npm run docker:build` - Build images
  - `npm run docker:up` - Start production
  - `npm run docker:dev` - Start development

### Rate Limiting

If you selected rate limiting during project creation, you can customize:

- **Default settings:**
  - API routes: 100 requests per 15 minutes
  - Auth routes: 5 requests per 15 minutes
  
- **Custom settings:** You can set:
  - API rate limit window (minutes)
  - API max requests per window
  - Auth rate limit window (minutes)
  - Auth max requests per window

**Example:** Set auth to 5 tries per 15 minutes, API to 200 per 30 minutes, etc.

### Health Check Endpoint

If you selected the health check endpoint during project creation, you'll get:

- **Health check route** (`routes/health.ts`) - `/health` endpoint
- Returns server status, uptime, and environment info
- Useful for monitoring and load balancers

**Example response:**
```json
{
  "success": true,
  "message": "Server is healthy",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "uptime": 123.456,
  "environment": "development"
}
```

### CI/CD Templates

If you selected CI/CD templates during project creation, you'll get:

- **GitHub Actions** (`.github/workflows/ci.yml`):
  - Runs tests on push/PR to main/develop branches
  - Includes MongoDB service for testing
  - Builds the project
  
- **GitLab CI** (`.gitlab-ci.yml`):
  - Test and build stages
  - MongoDB service included
  - Caches node_modules

### Jest Testing Setup

If you selected Jest testing setup, you'll get:

- **Jest configuration** (`jest.config.js`)
- **Test setup file** (`tests/setup.ts`) - MongoDB connection handling
- **Example test** (`tests/auth.test.ts`) - Auth endpoint tests
- **Test environment** (`.env.test`) - Test-specific environment variables
- **Test scripts** in `package.json`:
  - `npm test` - Run tests
  - `npm run test:watch` - Watch mode
  - `npm run test:coverage` - Coverage report

**Running tests:**
```bash
npm test
```

**Example test structure:**
```typescript
import request from 'supertest';
import app from '../server';

describe('Auth API', () => {
  it('should create a new user', async () => {
    const response = await request(app)
      .post('/api/v1/auth/signup')
      .send({ email: 'test@example.com', password: 'pass123', fullName: 'Test' })
      .expect(201);
    
    expect(response.body.success).toBe(true);
  });
});
```

## Docker Support

The generated project includes Docker configuration for both development and production environments.

### Quick Start with Docker

**Development mode (with hot reload):**
```bash
# Copy .env.example to .env and update values
cp .env.example .env

# Start services
npm run docker:dev
# or
docker-compose -f docker-compose.dev.yml up
```

**Production mode:**
```bash
# Copy .env.example to .env and update values
cp .env.example .env

# Build and start services
npm run docker:build
npm run docker:up
# or
docker-compose up --build
```

### Docker Commands

- `npm run docker:build` - Build Docker images
- `npm run docker:up` - Start containers (production)
- `npm run docker:down` - Stop and remove containers
- `npm run docker:dev` - Start in development mode with hot reload

### Docker Files

- **`Dockerfile`** - Production Dockerfile (builds TypeScript, runs optimized)
- **`Dockerfile.dev`** - Development Dockerfile (includes dev dependencies, hot reload)
- **`docker-compose.yml`** - Production setup (backend + MongoDB)
- **`docker-compose.dev.yml`** - Development setup (with volume mounts for hot reload)
- **`.dockerignore`** - Excludes unnecessary files from Docker builds
- **`.env.example`** - Example environment variables (copy to `.env`)

### Environment Variables for Docker

When using Docker, set `DB_URL` to:
```
DB_URL=mongodb://mongodb:27017/backend-db
```

The MongoDB service is automatically available at `mongodb` hostname within the Docker network.

### Accessing Services

- **Backend API**: `http://localhost:5500`
- **Swagger Docs**: `http://localhost:5500/api-docs`
- **MongoDB**: `localhost:27017` (from host machine)

## Contributing / local development (this CLI)

```bash
npm install
npm run build
npm link

# then from anywhere:
backend-cli my-backend-api
```

## License

MIT
