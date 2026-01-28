#!/usr/bin/env node

import * as fs from 'fs-extra';
import * as path from 'path';

const folders = [
  'config',
  'controllers',
  'emails',
  'middleware',
  'migrations',
  'models',
  'routes',
  'scripts',
  'services',
  'utils',
];

const templates = {
  '.env': `# Database Configuration
# Add your MongoDB connection string here
# Example: mongodb://localhost:27017/your-database-name
# Or use MongoDB Atlas: mongodb+srv://<username>:<password>@<cluster-url>/<database-name>?retryWrites=true&w=majority&appName=<app-name>
DB_URL=

# Access Token Secret
# Generate a secure random string for JWT token signing
# You can generate one using: node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
# Or use an online generator: https://randomkeygen.com/
ACCESS_TOKEN_SECRET=

# Server Port (optional, defaults to 5500)
ACCESS_PORT=5500
`,

  '.gitignore': `node_modules/
dist/
build/
.env
*.log
.DS_Store
.vscode/
.idea/
*.swp
*.swo
*~
`,

  '.prettierrc': `{
  "semi": true,
  "trailingComma": "es5",
  "singleQuote": true,
  "printWidth": 80,
  "tabWidth": 2
}
`,

  'server.ts': `import express, { Request, Response } from 'express';
import http from 'http';
import connectDB from './migrations/index';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import corsOptions from './config/corsOptions';
import { routes } from './routes/main';

const app = express();
const server = http.createServer(app);

// Setup CORS and JSON parsing
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Setup routes
routes(app);

// Root route
app.get('/', (req: Request, res: Response) => {
  res.send('Server Running');
});

// Connect to the database
connectDB();

// **Ensure port is a number**
const port = parseInt(process.env.ACCESS_PORT ?? '5500', 10);

if (process.env.NODE_ENV !== 'test') {
  server.listen(port, '0.0.0.0', () => {
    console.log(\`Server running on http://0.0.0.0:\${port}\`);
  });
}

export default app;
`,

  'tsconfig.json': `{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "moduleResolution": "node",
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true
  },
  "include": ["**/*"],
  "exclude": ["node_modules", "dist"]
}
`,

  'package.json': `{
  "name": "backend-project",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \\"Error: no test specified\\" && exit 1",
    "start": "node dist/server.js",
    "dev": "nodemon --exec ts-node server.ts",
    "format": "prettier --write .",
    "format:verify": "prettier --check .",
    "build": "tsc"
  },
  "keywords": [],
  "author": "",
  "license": "ISC",
  "dependencies": {
    "@types/node-cron": "^3.0.11",
    "bcryptjs": "^2.4.3",
    "body-parser": "^1.20.2",
    "cookie-parser": "^1.4.7",
    "cors": "^2.8.5",
    "date-fns": "^4.1.0",
    "dotenv": "^17.2.1",
    "express": "^5.1.0",
    "express-flash": "^0.0.2",
    "express-session": "^1.17.3",
    "jsonwebtoken": "^9.0.2",
    "mongoose": "^8.16.5",
    "node-cron": "^4.2.1",
    "nodemailer": "^7.0.3",
    "passport": "^0.6.0",
    "passport-local": "^1.0.0",
    "swagger-jsdoc": "^6.2.8",
    "swagger-ui-express": "^5.0.1"
  },
  "devDependencies": {
    "@types/bcryptjs": "^2.4.6",
    "@types/cookie-parser": "^1.4.8",
    "@types/cors": "^2.8.19",
    "@types/express": "^5.0.3",
    "@types/jsonwebtoken": "^9.0.6",
    "@types/mongoose": "^5.11.97",
    "@types/node": "^24.1.0",
    "@types/nodemailer": "^6.4.17",
    "nodemon": "^3.1.10",
    "prettier": "^3.3.3",
    "ts-node": "^10.9.2",
    "typescript": "^5.8.3"
  }
}
`,

  'config/allowedOrigins.ts': `const allowedOrigins: string[] = [
  'http://localhost:5500',
  'http://127.0.0.1:3000',
  'http://localhost:3000',
  'http://localhost:3001',
  'http://localhost:5174',
  'http://localhost:5173',
  'https://zamamedia.netlify.app',
];

export default allowedOrigins;
`,

  'config/corsOptions.ts': `import cors from 'cors';
import allowedOrigins from './allowedOrigins';

const corsOptions: cors.CorsOptions = {
  origin: (
    origin: string | undefined,
    callback: (err: Error | null, allowed?: boolean) => void
  ) => {
    if (allowedOrigins.indexOf(origin as string) !== -1 || !origin) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200,
};

export default corsOptions;
`,

  'config/roles_list.ts': `const ROLES_LIST = {
  TeamMember: 1001,
  Admin: 2003,
  SuperAdmin: 2706,
};

export default ROLES_LIST;
`,

  'migrations/index.ts': `import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

const connectDB = async (): Promise<void> => {
  try {
    mongoose.set('strictQuery', false);

    const connectOptions: mongoose.ConnectOptions = {
      // Add other options if needed, e.g., 'dbName' or 'autoIndex'
    };

    const connect = await mongoose.connect(
      process.env.DB_URL as string,
      connectOptions
    );

    console.log('MongoDB connected: ', connect.connection.host);
  } catch (err) {
    console.error(err);
  }
};

export default connectDB;
`,

  'routes/main.ts': `import { Application } from 'express';

export const routes = (app: Application): void => {
  // Add your routes here
  // Example:
  // app.use('/api/users', userRoutes);
};
`,
};

async function generateBackendStructure(targetPath: string): Promise<void> {
  try {
    // Check if directory already exists and has content
    if (await fs.pathExists(targetPath)) {
      const files = await fs.readdir(targetPath);
      if (files.length > 0) {
        console.error(`Error: Directory "${targetPath}" already exists and is not empty.`);
        process.exit(1);
      }
    }

    // Create target directory
    await fs.ensureDir(targetPath);

    // Create all folders
    console.log('Creating folders...');
    for (const folder of folders) {
      const folderPath = path.join(targetPath, folder);
      await fs.ensureDir(folderPath);
      console.log(`  ✓ Created folder: ${folder}/`);
    }

    // Create all root files
    console.log('\nCreating root files...');
    for (const [filename, content] of Object.entries(templates)) {
      if (!filename.includes('/')) {
        const filePath = path.join(targetPath, filename);
        await fs.writeFile(filePath, content);
        console.log(`  ✓ Created file: ${filename}`);
      }
    }

    // Create config files
    console.log('\nCreating config files...');
    for (const [filepath, content] of Object.entries(templates)) {
      if (filepath.startsWith('config/')) {
        const fullPath = path.join(targetPath, filepath);
        await fs.ensureDir(path.dirname(fullPath));
        await fs.writeFile(fullPath, content);
        console.log(`  ✓ Created file: ${filepath}`);
      }
    }

    // Create migrations file
    console.log('\nCreating migrations file...');
    const migrationsPath = path.join(targetPath, 'migrations/index.ts');
    await fs.writeFile(migrationsPath, templates['migrations/index.ts']);
    console.log(`  ✓ Created file: migrations/index.ts`);

    // Create routes file
    console.log('\nCreating routes file...');
    const routesPath = path.join(targetPath, 'routes/main.ts');
    await fs.writeFile(routesPath, templates['routes/main.ts']);
    console.log(`  ✓ Created file: routes/main.ts`);

    console.log('\n✅ Backend structure generated successfully!');
    console.log(`\nNext steps:`);
    console.log(`  1. cd ${targetPath}`);
    console.log(`  2. npm install`);
    console.log(`  3. Update .env with your DB_URL and ACCESS_TOKEN_SECRET`);
    console.log(`  4. npm run dev`);
  } catch (error) {
    console.error('Error generating backend structure:', error);
    process.exit(1);
  }
}

// Main execution
const args = process.argv.slice(2);
const projectName = args[0] || 'backend-project';
const targetPath = path.resolve(process.cwd(), projectName);

console.log(`Generating backend structure in: ${targetPath}\n`);
generateBackendStructure(targetPath);
