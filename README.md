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

### Example

```bash
backend-cli my-backend-api
```

## Generated project structure

```bash
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
- **Route entrypoint**: `routes/main.ts` (placeholder for your routes)

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
