# Backend CLI

A CLI tool to quickly generate a backend project structure with TypeScript, Express, and MongoDB.

## Installation

Install globally from npm:

```bash
npm install -g express-backend-scaffold
```

## Usage

After installation, use the `backend-cli` command to generate a new backend project:

```bash
backend-cli [project-name]
```

If no project name is provided, it will default to `backend-project`.

### Example

```bash
backend-cli my-backend-api
```

This will create a directory called `my-backend-api` with the complete backend structure.

### Local Development (for contributors)

If you want to contribute or test locally:

```bash
# Clone the repository
git clone <repository-url>
cd backend-cli

# Install dependencies
npm install

# Build the project
npm run build

# Link for local testing
npm link
```

### Example

```bash
backend-cli my-backend-api
```

This will create a directory called `my-backend-api` with the following structure:

```
my-backend-api/
├── config/
│   ├── allowedOrigins.ts
│   ├── corsOptions.ts
│   └── roles_list.ts
├── controllers/
├── emails/
├── middleware/
├── migrations/
│   └── index.ts
├── models/
├── routes/
│   └── main.ts
├── scripts/
├── services/
├── utils/
├── .env
├── .gitignore
├── .prettierrc
├── package.json
├── server.ts
└── tsconfig.json
```

## Generated Structure

### Folders
- **config**: Configuration files for CORS, allowed origins, and roles
- **controllers**: Route controllers
- **emails**: Email templates and utilities
- **middleware**: Express middleware functions
- **migrations**: Database migration files
- **models**: Mongoose models
- **routes**: Route definitions
- **scripts**: Utility scripts
- **services**: Business logic services
- **utils**: Helper utilities

### Root Files
- **.env**: Environment variables (DB_URL and ACCESS_TOKEN_SECRET)
- **.gitignore**: Git ignore patterns
- **.prettierrc**: Prettier configuration
- **package.json**: Project dependencies and scripts
- **server.ts**: Main server file
- **tsconfig.json**: TypeScript configuration

## Next Steps

After generating your project:

1. Navigate to the project directory:
   ```bash
   cd my-backend-api
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Update `.env` file:
   - Add your MongoDB connection string to `DB_URL`
   - Generate and add an access token secret to `ACCESS_TOKEN_SECRET`
     ```bash
     node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
     ```

4. Start the development server:
   ```bash
   npm run dev
   ```

## Configuration

### Database Connection
The `.env` file includes a `DB_URL` variable. Update it with your MongoDB connection string:
- Local: `mongodb://localhost:27017/your-database-name`
- MongoDB Atlas: `mongodb+srv://username:password@cluster.mongodb.net/database-name`

### Access Token Secret
Generate a secure random string for JWT token signing. You can use:
- Node.js: `node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"`
- Online generator: https://randomkeygen.com/

## Dependencies

The generated project includes:
- **express**: Web framework
- **mongoose**: MongoDB ODM
- **cors**: CORS middleware
- **cookie-parser**: Cookie parsing middleware
- **dotenv**: Environment variable management

## Development

To work on this CLI tool:

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Run in development mode
npm run dev
```

## License

MIT
