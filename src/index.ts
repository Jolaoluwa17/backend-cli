#!/usr/bin/env node

import * as fs from 'fs-extra';
import * as path from 'path';
import inquirer from 'inquirer';

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
  
  '.dockerignore': `node_modules
dist
build
.git
.gitignore
.env
*.log
.DS_Store
.vscode
.idea
*.md
npm-debug.log*
yarn-debug.log*
yarn-error.log*
`,
  
  'Dockerfile': `# Use Node.js LTS version
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Expose port
EXPOSE 5500

# Start the application
CMD ["npm", "start"]
`,
  
  'Dockerfile.dev': `# Development Dockerfile with hot reload
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install all dependencies (including dev dependencies)
RUN npm install

# Copy source code
COPY . .

# Expose port
EXPOSE 5500

# Start the application in development mode
CMD ["npm", "run", "dev"]
`,
  
  'docker-compose.yml': `version: '3.8'

services:
  backend:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: backend-app
    ports:
      - "5500:5500"
    environment:
      - NODE_ENV=production
      - DB_URL=mongodb://mongodb:27017/backend-db
      - ACCESS_TOKEN_SECRET=\${ACCESS_TOKEN_SECRET}
      - ACCESS_PORT=5500
    depends_on:
      - mongodb
    restart: unless-stopped
    networks:
      - backend-network

  mongodb:
    image: mongo:7
    container_name: backend-mongodb
    ports:
      - "27017:27017"
    environment:
      - MONGO_INITDB_DATABASE=backend-db
    volumes:
      - mongodb-data:/data/db
    restart: unless-stopped
    networks:
      - backend-network

volumes:
  mongodb-data:

networks:
  backend-network:
    driver: bridge
`,
  
  'docker-compose.dev.yml': `version: '3.8'

services:
  backend:
    build:
      context: .
      dockerfile: Dockerfile.dev
    container_name: backend-app-dev
    ports:
      - "5500:5500"
    environment:
      - NODE_ENV=development
      - DB_URL=mongodb://mongodb:27017/backend-db
      - ACCESS_TOKEN_SECRET=\${ACCESS_TOKEN_SECRET:-dev-secret-key-change-in-production}
      - ACCESS_PORT=5500
    volumes:
      - .:/app
      - /app/node_modules
    depends_on:
      - mongodb
    restart: unless-stopped
    networks:
      - backend-network

  mongodb:
    image: mongo:7
    container_name: backend-mongodb-dev
    ports:
      - "27017:27017"
    environment:
      - MONGO_INITDB_DATABASE=backend-db
    volumes:
      - mongodb-data-dev:/data/db
    restart: unless-stopped
    networks:
      - backend-network

volumes:
  mongodb-data-dev:

networks:
  backend-network:
    driver: bridge
`,
  
  '.env.example': `# Database Configuration
# For Docker: mongodb://mongodb:27017/backend-db
# For local: mongodb://localhost:27017/your-database-name
# For MongoDB Atlas: mongodb+srv://<username>:<password>@<cluster-url>/<database-name>?retryWrites=true&w=majority&appName=<app-name>
DB_URL=mongodb://mongodb:27017/backend-db

# Access Token Secret
# Generate a secure random string for JWT token signing
# You can generate one using: node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
ACCESS_TOKEN_SECRET=your-secret-key-here

# Server Port (optional, defaults to 5500)
ACCESS_PORT=5500
`,

  '.env.test': `# Test Environment Variables
DB_URL=mongodb://localhost:27017/test-db
ACCESS_TOKEN_SECRET=test-secret-key-for-testing-only
ACCESS_PORT=5501
NODE_ENV=test
`,

  '.prettierrc': `{
  "semi": true,
  "trailingComma": "es5",
  "singleQuote": true,
  "printWidth": 80,
  "tabWidth": 2
}
`,

  'routes/health.ts': `import { Router, Request, Response } from 'express';

const router = Router();

/**
 * @swagger
 * /health:
 *   get:
 *     summary: Health check endpoint
 *     tags: [Health]
 *     responses:
 *       200:
 *         description: Server is healthy
 */
router.get('/health', (req: Request, res: Response) => {
  res.status(200).json({
    success: true,
    message: 'Server is healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development',
  });
});

export default router;
`,

  'server.ts': `import express, { Request, Response } from 'express';
import http from 'http';
import connectDB from './migrations/index';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import corsOptions from './config/corsOptions';
import { routes } from './routes/main';
{{SWAGGER_IMPORTS}}
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import { errorHandler } from './middleware/errorHandler';
{{RATE_LIMIT_IMPORTS}}
import { validateEnv } from './utils/validateEnv';

dotenv.config();

// Validate environment variables
try {
  validateEnv();
} catch (error: any) {
  console.error('❌ Environment validation failed:', error.message);
  process.exit(1);
}

const app = express();
const server = http.createServer(app);

// Setup CORS and JSON parsing
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

{{RATE_LIMIT_MIDDLEWARE}}

{{SWAGGER_MIDDLEWARE}}

// Root route
app.get('/', (req: Request, res: Response) => {
  res.send('Server Running');
});

// Setup routes
routes(app);

// Error handling middleware (must be last)
app.use(errorHandler);

// **Ensure port is a number**
const port = parseInt(process.env.ACCESS_PORT ?? '5500', 10);

// Connect to the database and start server
const startServer = async (): Promise<void> => {
  // Connect to MongoDB
  const dbConnected = await connectDB();

  if (process.env.NODE_ENV !== 'test') {
    server.listen(port, '0.0.0.0', () => {
      console.log('\\n' + '='.repeat(60));
      console.log('🚀 Server Started Successfully');
      console.log('='.repeat(60));
      console.log(\`\\n📡 Backend URL:     http://localhost:\${port}\`);
{{SWAGGER_CONSOLE}}
{{HEALTH_CHECK_CONSOLE}}
      console.log(\`\\n💾 MongoDB Status:  \${dbConnected ? '✅ Connected' : '❌ Not Connected'}\`);
      if (dbConnected && mongoose.connection.host) {
        console.log(\`   Host: \${mongoose.connection.host}\`);
        console.log(\`   Database: \${mongoose.connection.name}\`);
      }
      console.log('\\n' + '='.repeat(60) + '\\n');
    });
  }
};

startServer();

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
    "start": "node dist/server.js",
    "dev": "nodemon --exec ts-node server.ts",
    "format": "prettier --write .",
    "format:verify": "prettier --check .",
    "build": "tsc",
    "docker:build": "docker-compose build",
    "docker:up": "docker-compose up",
    "docker:down": "docker-compose down",
    "docker:dev": "docker-compose -f docker-compose.dev.yml up"
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
    "swagger-ui-express": "^5.0.1",
    "express-rate-limit": "^7.1.5"
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
    "@types/swagger-jsdoc": "^6.0.1",
    "@types/swagger-ui-express": "^4.1.6",
    "@types/express-rate-limit": "^6.0.0",
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

  'config/swagger.ts': `import swaggerJsdoc from 'swagger-jsdoc';

const options: swaggerJsdoc.Options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Backend API',
      version: '1.0.0',
      description: 'API documentation for Backend Project',
      contact: {
        name: 'API Support',
      },
    },
    servers: [
      {
        url: \`http://localhost:\${process.env.ACCESS_PORT || 5500}\`,
        description: 'Development server',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
  },
  apis: ['./routes/**/*.ts', './server.ts'], // Path to the API files
};

const swaggerSpec = swaggerJsdoc(options);

export default swaggerSpec;
`,

  'migrations/index.ts': `import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

const connectDB = async (): Promise<boolean> => {
  try {
    mongoose.set('strictQuery', false);

    const connectOptions: mongoose.ConnectOptions = {
      // Add other options if needed, e.g., 'dbName' or 'autoIndex'
    };

    const connect = await mongoose.connect(
      process.env.DB_URL as string,
      connectOptions
    );

    return true;
  } catch (err) {
    console.error('MongoDB connection error:', err);
    return false;
  }
};

export default connectDB;
`,

  'routes/main.ts': `import { Application } from 'express';
import authRoutes from './auth';

export const routes = (app: Application): void => {
  // API versioning - all routes are under /api/v1
  // Auth routes
  app.use('/api/v1/auth', authRoutes);

  // Add your routes here
  // Example:
  // app.use('/api/v1/users', userRoutes);
  // app.use('/api/v1/products', productRoutes);
};
`,

  'models/User.ts': `import mongoose, { Schema, Document } from 'mongoose';
import bcrypt from 'bcryptjs';
import ROLES_LIST from '../config/roles_list';

export interface IUser extends Document {
  email: string;
  password: string;
  fullName: string;
  roles: {
    TeamMember: number;
    Admin: number;
    SuperAdmin: number;
  };
  createdAt: Date;
  updatedAt: Date;
  comparePassword(candidatePassword: string): Promise<boolean>;
}

const UserSchema: Schema = new Schema(
  {
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\\S+@\\S+\\.\\S+$/, 'Please provide a valid email'],
    },
    password: {
      type: String,
      required: [true, 'Password is required'],
      minlength: [6, 'Password must be at least 6 characters'],
      select: false, // Don't return password by default
    },
    fullName: {
      type: String,
      required: [true, 'Full name is required'],
      trim: true,
    },
    roles: {
      TeamMember: {
        type: Number,
        default: ROLES_LIST.TeamMember,
      },
      Admin: {
        type: Number,
        default: 0,
      },
      SuperAdmin: {
        type: Number,
        default: 0,
      },
    },
  },
  {
    timestamps: true,
  }
);

// Hash password before saving
UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    return next();
  }

  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error: any) {
    next(error);
  }
});

// Method to compare password
UserSchema.methods.comparePassword = async function (
  candidatePassword: string
): Promise<boolean> {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model<IUser>('User', UserSchema);

export default User;
`,

  'controllers/authController.ts': `import { Request, Response } from 'express';
import User from '../models/User';
import jwt from 'jsonwebtoken';

/**
 * @swagger
 * components:
 *   schemas:
 *     User:
 *       type: object
 *       required:
 *         - email
 *         - password
 *         - fullName
 *       properties:
 *         email:
 *           type: string
 *           format: email
 *         password:
 *           type: string
 *           minLength: 6
 *         fullName:
 *           type: string
 *     AuthResponse:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *         message:
 *           type: string
 *         data:
 *           type: object
 *           properties:
 *             user:
 *               $ref: '#/components/schemas/User'
 *             accessToken:
 *               type: string
 */

// Generate JWT token
{{GENERATE_TOKEN_SIGNATURE}}
const generateToken = (userId: string{{GENERATE_TOKEN_ROLES_PARAM}}): string => {
  return jwt.sign(
    { userId{{GENERATE_TOKEN_ROLES_PAYLOAD}} },
    process.env.ACCESS_TOKEN_SECRET as string,
    {
      expiresIn: '7d',
    }
  );
};

/**
 * @swagger
 * /api/v1/auth/signup:
 *   post:
 *     summary: Register a new user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/User'
 *     responses:
 *       201:
 *         description: User created successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AuthResponse'
 *       400:
 *         description: Bad request (validation error or user already exists)
 *       500:
 *         description: Server error
 */
export const signup = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password, fullName } = req.body;

    // Validation
    if (!email || !password || !fullName) {
      res.status(400).json({
        success: false,
        message: 'Please provide email, password, and full name',
      });
      return;
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      res.status(400).json({
        success: false,
        message: 'User with this email already exists',
      });
      return;
    }

    // Create new user
    const user = new User({
      email,
      password,
      fullName,
    });

    await user.save();

    // Generate token
    const accessToken = generateToken(user._id.toString(){{GENERATE_TOKEN_CALL}});

    // Remove password from response
    const userResponse = user.toObject();
    delete userResponse.password;

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      data: {
        user: userResponse,
        accessToken,
      },
    });
  } catch (error: any) {
    console.error('Signup error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error creating user',
    });
  }
};

/**
 * @swagger
 * /api/v1/auth/login:
 *   post:
 *     summary: Login user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AuthResponse'
 *       401:
 *         description: Invalid credentials
 *       500:
 *         description: Server error
 */
export const login = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      res.status(400).json({
        success: false,
        message: 'Please provide email and password',
      });
      return;
    }

    // Find user and include password for comparison
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      res.status(401).json({
        success: false,
        message: 'Invalid email or password',
      });
      return;
    }

    // Compare password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      res.status(401).json({
        success: false,
        message: 'Invalid email or password',
      });
      return;
    }

    // Generate token
    const accessToken = generateToken(user._id.toString(){{GENERATE_TOKEN_CALL}});

    // Remove password from response
    const userResponse = user.toObject();
    delete userResponse.password;

    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: {
        user: userResponse,
        accessToken,
      },
    });
  } catch (error: any) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error logging in',
    });
  }
};
`,

  'routes/auth.ts': `import { Router } from 'express';
import { signup, login } from '../controllers/authController';
import { authLimiter } from '../middleware/rateLimiter';

const router = Router();

/**
 * @swagger
 * tags:
 *   name: Authentication
 *   description: User authentication endpoints
 */

// Apply rate limiting to auth routes
router.post('/signup', authLimiter, signup);
router.post('/login', authLimiter, login);

export default router;
`,

  'middleware/verifyJWT.ts': `import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

export interface AuthRequest extends Request {
  userId?: string;
  roles?: {
    TeamMember: number;
    Admin: number;
    SuperAdmin: number;
  };
}

/**
 * Middleware to verify JWT token
 * Adds userId and roles to request object if token is valid
 */
export const verifyJWT = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({
        success: false,
        message: 'No token provided or invalid format',
      });
      return;
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    const decoded = jwt.verify(
      token,
      process.env.ACCESS_TOKEN_SECRET as string
    ) as {
      userId: string;
      roles: {
        TeamMember: number;
        Admin: number;
        SuperAdmin: number;
      };
    };

    req.userId = decoded.userId;
    req.roles = decoded.roles;
    next();
  } catch (error: any) {
    if (error.name === 'TokenExpiredError') {
      res.status(401).json({
        success: false,
        message: 'Token expired',
      });
      return;
    }

    if (error.name === 'JsonWebTokenError') {
      res.status(401).json({
        success: false,
        message: 'Invalid token',
      });
      return;
    }

    res.status(500).json({
      success: false,
      message: 'Error verifying token',
    });
  }
};
`,

  'middleware/verifyRoles.ts': `import { Response, NextFunction } from 'express';
import ROLES_LIST from '../config/roles_list';
import { AuthRequest } from './verifyJWT';

/**
 * Middleware to verify user roles
 * Must be used after verifyJWT middleware
 * 
 * @param allowedRoles - Array of role names that are allowed to access the route
 * @returns Middleware function
 * 
 * @example
 * // Allow only Admin and SuperAdmin
 * router.get('/admin-only', verifyJWT, verifyRoles(['Admin', 'SuperAdmin']), handler);
 * 
 * // Allow only SuperAdmin
 * router.delete('/super-admin-only', verifyJWT, verifyRoles(['SuperAdmin']), handler);
 */
export const verifyRoles = (allowedRoles: string[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction): void => {
    if (!req.roles) {
      res.status(401).json({
        success: false,
        message: 'Unauthorized: No roles found. Please use verifyJWT middleware first.',
      });
      return;
    }

    // Check if user has any of the allowed roles
    const hasAccess = allowedRoles.some((roleName) => {
      const roleValue = ROLES_LIST[roleName as keyof typeof ROLES_LIST];
      if (!roleValue) return false;

      // Check if user has this role
      return req.roles![roleName as keyof typeof req.roles] === roleValue;
    });

    if (!hasAccess) {
      res.status(403).json({
        success: false,
        message: \`Forbidden: You don't have permission to access this resource. Required roles: \${allowedRoles.join(', ')}\`,
      });
      return;
    }

    next();
  };
};
`,

  'middleware/errorHandler.ts': `import { Request, Response, NextFunction } from 'express';

export interface AppError extends Error {
  statusCode?: number;
  isOperational?: boolean;
}

/**
 * Custom error class for application errors
 */
export class AppError extends Error implements AppError {
  statusCode: number;
  isOperational: boolean;

  constructor(message: string, statusCode: number = 500) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Global error handling middleware
 * Should be used as the last middleware in the app
 */
export const errorHandler = (
  err: AppError | Error,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  let error = { ...err } as AppError;
  error.message = err.message;

  // Log error for debugging
  console.error('Error:', err);

  // Mongoose bad ObjectId
  if (err.name === 'CastError') {
    const message = 'Resource not found';
    error = new AppError(message, 404);
  }

  // Mongoose duplicate key
  if ((err as any).code === 11000) {
    const message = 'Duplicate field value entered';
    error = new AppError(message, 400);
  }

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const message = Object.values((err as any).errors)
      .map((val: any) => val.message)
      .join(', ');
    error = new AppError(message, 400);
  }

  res.status(error.statusCode || 500).json({
    success: false,
    message: error.message || 'Server Error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
  });
};
`,

  'middleware/rateLimiter.ts': `import rateLimit from 'express-rate-limit';

// Rate limit configuration
// You can customize these values based on your needs
const API_WINDOW_MS = {{API_WINDOW_MS}}; // Window in milliseconds
const API_MAX_REQUESTS = {{API_MAX}}; // Max requests per window
const AUTH_WINDOW_MS = {{AUTH_WINDOW_MS}}; // Auth window in milliseconds
const AUTH_MAX_REQUESTS = {{AUTH_MAX}}; // Max auth requests per window

/**
 * General API rate limiter
 * Limits requests per IP based on configuration
 */
export const apiLimiter = rateLimit({
  windowMs: API_WINDOW_MS,
  max: API_MAX_REQUESTS,
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later.',
  },
  standardHeaders: true, // Return rate limit info in the RateLimit-* headers
  legacyHeaders: false, // Disable the X-RateLimit-* headers
});

/**
 * Auth endpoints rate limiter
 * Limits authentication requests per IP based on configuration
 */
export const authLimiter = rateLimit({
  windowMs: AUTH_WINDOW_MS,
  max: AUTH_MAX_REQUESTS,
  message: {
    success: false,
    message: 'Too many authentication attempts, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Don't count successful requests
});
`,

  'utils/validateEnv.ts': `/**
 * Validates required environment variables
 * Throws error if any required variable is missing
 */
export const validateEnv = (): void => {
  const requiredEnvVars = ['DB_URL', 'ACCESS_TOKEN_SECRET'];

  const missingVars = requiredEnvVars.filter(
    (varName) => !process.env[varName]
  );

  if (missingVars.length > 0) {
    throw new Error(
      \`Missing required environment variables: \${missingVars.join(', ')}\`
    );
  }
};
`,

  'utils/pagination.ts': `export interface PaginationOptions {
  page?: number;
  limit?: number;
  sort?: string;
  order?: 'asc' | 'desc';
}

export interface PaginationResult<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
}

/**
 * Creates pagination options from query parameters
 */
export const getPaginationOptions = (
  query: any
): PaginationOptions => {
  const page = Math.max(1, parseInt(query.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(query.limit) || 10));
  const sort = query.sort || 'createdAt';
  const order = query.order === 'asc' ? 'asc' : 'desc';

  return { page, limit, sort, order };
};

/**
 * Creates pagination result
 */
export const createPaginationResult = <T>(
  data: T[],
  total: number,
  page: number,
  limit: number
): PaginationResult<T> => {
  const totalPages = Math.ceil(total / limit);

  return {
    data,
    pagination: {
      page,
      limit,
      total,
      totalPages,
      hasNext: page < totalPages,
      hasPrev: page > 1,
    },
  };
};
`,

  'utils/validation.ts': `/**
 * Validates email format
 */
export const isValidEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

/**
 * Validates required fields in request body
 */
export const validateRequired = (
  data: Record<string, any>,
  fields: string[]
): { isValid: boolean; missingFields: string[] } => {
  const missingFields = fields.filter((field) => !data[field]);

  return {
    isValid: missingFields.length === 0,
    missingFields,
  };
};

/**
 * Sanitizes string input
 */
export const sanitizeString = (input: string): string => {
  return input.trim().replace(/[<>]/g, '');
};
`,

  '.github/workflows/ci.yml': `name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      mongodb:
        image: mongo:7
        ports:
          - 27017:27017
        options: >-
          --health-cmd "mongosh --eval 'db.runCommand({ ping: 1 })'"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run linter
        run: npm run lint || echo "Linter not configured"

      - name: Run tests
        run: npm test
        env:
          DB_URL: mongodb://localhost:27017/test-db
          ACCESS_TOKEN_SECRET: test-secret-key-for-ci
          NODE_ENV: test

      - name: Build
        run: npm run build
`,

  '.gitlab-ci.yml': `image: node:18

services:
  - mongo:7

variables:
  MONGODB_DATABASE: test-db
  DB_URL: mongodb://mongo:27017/test-db
  ACCESS_TOKEN_SECRET: test-secret-key-for-ci
  NODE_ENV: test

cache:
  paths:
    - node_modules/

stages:
  - test
  - build

before_script:
  - npm ci

test:
  stage: test
  script:
    - npm run lint || echo "Linter not configured"
    - npm test

build:
  stage: build
  script:
    - npm run build
  only:
    - main
    - develop
`,

  'jest.config.js': `module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/*.spec.ts',
    '!src/**/*.test.ts',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
  testTimeout: 10000,
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
};
`,

  'tests/setup.ts': `import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config({ path: '.env.test' });

// Setup before all tests
beforeAll(async () => {
  const mongoUrl = process.env.DB_URL || 'mongodb://localhost:27017/test-db';
  await mongoose.connect(mongoUrl);
});

// Cleanup after all tests
afterAll(async () => {
  await mongoose.connection.dropDatabase();
  await mongoose.connection.close();
});

// Cleanup after each test
afterEach(async () => {
  const collections = mongoose.connection.collections;
  for (const key in collections) {
    await collections[key].deleteMany({});
  }
});
`,

  'tests/auth.test.ts': `import request from 'supertest';
import app from '../server';
import User from '../models/User';

describe('Auth API', () => {
  describe('POST /api/v1/auth/signup', () => {
    it('should create a new user', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'password123',
        fullName: 'Test User',
      };

      const response = await request(app)
        .post('/api/v1/auth/signup')
        .send(userData)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.user).toHaveProperty('email', userData.email);
      expect(response.body.data.user).toHaveProperty('fullName', userData.fullName);
      expect(response.body.data).toHaveProperty('accessToken');
      expect(response.body.data.user).not.toHaveProperty('password');
    });

    it('should not create user with duplicate email', async () => {
      const userData = {
        email: 'duplicate@example.com',
        password: 'password123',
        fullName: 'Test User',
      };

      // Create first user
      await request(app).post('/api/v1/auth/signup').send(userData);

      // Try to create duplicate
      const response = await request(app)
        .post('/api/v1/auth/signup')
        .send(userData)
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    it('should validate required fields', async () => {
      const response = await request(app)
        .post('/api/v1/auth/signup')
        .send({ email: 'test@example.com' })
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('POST /api/v1/auth/login', () => {
    beforeEach(async () => {
      const user = new User({
        email: 'login@example.com',
        password: 'password123',
        fullName: 'Login User',
      });
      await user.save();
    });

    it('should login with valid credentials', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'login@example.com',
          password: 'password123',
        })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('accessToken');
      expect(response.body.data.user).toHaveProperty('email', 'login@example.com');
    });

    it('should not login with invalid credentials', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'login@example.com',
          password: 'wrongpassword',
        })
        .expect(401);

      expect(response.body.success).toBe(false);
    });
  });
});
`,
};

interface RateLimitConfig {
  enabled: boolean;
  apiWindowMs: number;
  apiMax: number;
  authWindowMs: number;
  authMax: number;
}

interface GenerationOptions {
  includeCI: boolean;
  includeTests: boolean;
  includeHealthCheck: boolean;
  includeAuth: boolean;
  includeRoleManagement: boolean;
  includeSwagger: boolean;
  includeDocker: boolean;
  rateLimit: RateLimitConfig;
}

async function generateBackendStructure(
  targetPath: string,
  options: GenerationOptions
): Promise<void> {
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

    // Create all root files (conditionally)
    console.log('\nCreating root files...');
    for (const [filename, content] of Object.entries(templates)) {
      if (!filename.includes('/')) {
        // Skip Docker files if not included
        if ((filename === 'Dockerfile' || filename === 'Dockerfile.dev' || 
             filename === 'docker-compose.yml' || filename === 'docker-compose.dev.yml' || 
             filename === '.dockerignore') && !options.includeDocker) {
          continue;
        }
        
        let fileContent = content;
        
        // Process server.ts with placeholders
        if (filename === 'server.ts') {
          fileContent = fileContent
            .replace('{{SWAGGER_IMPORTS}}', options.includeSwagger 
              ? `import swaggerUi from 'swagger-ui-express';\nimport swaggerSpec from './config/swagger';` 
              : '')
            .replace('{{RATE_LIMIT_IMPORTS}}', options.rateLimit.enabled 
              ? `import { apiLimiter } from './middleware/rateLimiter';` 
              : '')
            .replace('{{RATE_LIMIT_MIDDLEWARE}}', options.rateLimit.enabled 
              ? `// Apply rate limiting to all API routes\napp.use('/api', apiLimiter);` 
              : '')
            .replace('{{SWAGGER_MIDDLEWARE}}', options.includeSwagger 
              ? `// Swagger documentation\napp.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));` 
              : '')
            .replace('{{SWAGGER_CONSOLE}}', options.includeSwagger 
              ? `      console.log(\`📚 Swagger Docs:    http://localhost:\${port}/api-docs\`);` 
              : '')
            .replace('{{HEALTH_CHECK_CONSOLE}}', options.includeHealthCheck 
              ? `      console.log(\`🏥 Health Check:    http://localhost:\${port}/health\`);` 
              : '');
        }
        
        const filePath = path.join(targetPath, filename);
        await fs.writeFile(filePath, fileContent);
        console.log(`  ✓ Created file: ${filename}`);
      }
    }

    // Create config files (conditionally)
    console.log('\nCreating config files...');
    for (const [filepath, content] of Object.entries(templates)) {
      if (filepath.startsWith('config/')) {
        // Skip Swagger config if not included
        if (filepath === 'config/swagger.ts' && !options.includeSwagger) {
          continue;
        }
        
        // Skip roles_list if role management is not included
        if (filepath === 'config/roles_list.ts' && !options.includeRoleManagement) {
          continue;
        }
        
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

    // Create routes files (conditionally)
    console.log('\nCreating routes files...');
    let routesMainContent = templates['routes/main.ts'];
    
    // Conditionally include auth routes
    if (options.includeAuth) {
      const authRoutesPath = path.join(targetPath, 'routes/auth.ts');
      let authRoutesContent = templates['routes/auth.ts'];
      
      // Add rate limiting to auth routes if enabled
      if (options.rateLimit.enabled) {
        authRoutesContent = authRoutesContent.replace(
          "import { signup, login } from '../controllers/authController';",
          "import { signup, login } from '../controllers/authController';\nimport { authLimiter } from '../middleware/rateLimiter';"
        );
        authRoutesContent = authRoutesContent.replace(
          "router.post('/signup', signup);",
          "router.post('/signup', authLimiter, signup);"
        );
        authRoutesContent = authRoutesContent.replace(
          "router.post('/login', login);",
          "router.post('/login', authLimiter, login);"
        );
      }
      
      await fs.writeFile(authRoutesPath, authRoutesContent);
      console.log(`  ✓ Created file: routes/auth.ts`);
      
      // Update routes/main.ts with auth routes
      routesMainContent = routesMainContent.replace(
        '{{AUTH_ROUTES_IMPORT}}',
        "import authRoutes from './auth';"
      );
      routesMainContent = routesMainContent.replace(
        '{{AUTH_ROUTES}}',
        "// Auth routes\n  app.use('/api/v1/auth', authRoutes);"
      );
    } else {
      // Remove auth routes from main.ts
      routesMainContent = routesMainContent.replace(
        '{{AUTH_ROUTES_IMPORT}}',
        ''
      );
      routesMainContent = routesMainContent.replace(
        '{{AUTH_ROUTES}}',
        '// Auth routes (not included)'
      );
    }
    
    const routesPath = path.join(targetPath, 'routes/main.ts');
    await fs.writeFile(routesPath, routesMainContent);
    console.log(`  ✓ Created file: routes/main.ts`);

    // Conditionally create health check route
    if (options.includeHealthCheck) {
      const healthRoutesPath = path.join(targetPath, 'routes/health.ts');
      await fs.writeFile(healthRoutesPath, templates['routes/health.ts']);
      console.log(`  ✓ Created file: routes/health.ts`);
      
      // Update routes/main.ts to include health check
      const routesMainPath = path.join(targetPath, 'routes/main.ts');
      let routesMainContent = await fs.readFile(routesMainPath, 'utf-8');
      routesMainContent = routesMainContent.replace(
        /\/\/ Health check route \(if included\)\n\s*\/\/ import healthRoutes from '\.\/health';\n\s*\/\/ app\.use\('\/', healthRoutes\);/,
        `// Health check route
import healthRoutes from './health';
app.use('/', healthRoutes);`
      );
      await fs.writeFile(routesMainPath, routesMainContent);
      
      // Update server.ts to show health check in startup message
      const serverPath = path.join(targetPath, 'server.ts');
      let serverContent = await fs.readFile(serverPath, 'utf-8');
      serverContent = serverContent.replace(
        /console\.log\(`\\n📡 Backend URL:     http:\/\/localhost:\$\{port\}`\);\n\s*console\.log\(`📚 Swagger Docs:    http:\/\/localhost:\$\{port\}\/api-docs`\);\n\s*console\.log\(`\\n💾 MongoDB Status:/,
        `console.log(\`\\n📡 Backend URL:     http://localhost:\${port}\`);
      console.log(\`📚 Swagger Docs:    http://localhost:\${port}/api-docs\`);
      console.log(\`🏥 Health Check:    http://localhost:\${port}/health\`);
      console.log(\`\\n💾 MongoDB Status:`
      );
      await fs.writeFile(serverPath, serverContent);
      console.log(`  ✓ Updated routes/main.ts and server.ts with health check`);
    }

    // Create model files (conditionally)
    if (options.includeAuth) {
      console.log('\nCreating model files...');
      const userModelPath = path.join(targetPath, 'models/User.ts');
      let userModelContent = templates['models/User.ts'];
      
      // Remove roles if role management is not included
      if (!options.includeRoleManagement) {
        userModelContent = userModelContent.replace(
          /import ROLES_LIST from '\.\.\/config\/roles_list';\n/,
          ''
        );
        userModelContent = userModelContent.replace(
          /roles: \{[^}]+\};\n\s*/g,
          ''
        );
        userModelContent = userModelContent.replace(
          /roles: \{[^}]+\},\n\s*/g,
          ''
        );
        // Remove roles field from schema
        userModelContent = userModelContent.replace(
          /,\s*roles: \{[^}]+\}\n\s*\)/,
          '\n  )'
        );
      }
      
      await fs.writeFile(userModelPath, userModelContent);
      console.log(`  ✓ Created file: models/User.ts`);
    }

    // Create controller files (conditionally)
    if (options.includeAuth) {
      console.log('\nCreating controller files...');
      const authControllerPath = path.join(targetPath, 'controllers/authController.ts');
      let authControllerContent = templates['controllers/authController.ts'];
      
      // Update auth controller to conditionally include roles
      if (options.includeRoleManagement) {
        authControllerContent = authControllerContent.replace(
          '{{GENERATE_TOKEN_SIGNATURE}}',
          ''
        );
        authControllerContent = authControllerContent.replace(
          '{{GENERATE_TOKEN_ROLES_PARAM}}',
          ', roles: { TeamMember: number; Admin: number; SuperAdmin: number }'
        );
        authControllerContent = authControllerContent.replace(
          '{{GENERATE_TOKEN_ROLES_PAYLOAD}}',
          ', roles'
        );
        authControllerContent = authControllerContent.replace(
          '{{GENERATE_TOKEN_CALL}}',
          ', user.roles'
        );
      } else {
        authControllerContent = authControllerContent.replace(
          '{{GENERATE_TOKEN_SIGNATURE}}',
          ''
        );
        authControllerContent = authControllerContent.replace(
          '{{GENERATE_TOKEN_ROLES_PARAM}}',
          ''
        );
        authControllerContent = authControllerContent.replace(
          '{{GENERATE_TOKEN_ROLES_PAYLOAD}}',
          ''
        );
        authControllerContent = authControllerContent.replace(
          '{{GENERATE_TOKEN_CALL}}',
          ''
        );
      }
      
      await fs.writeFile(authControllerPath, authControllerContent);
      console.log(`  ✓ Created file: controllers/authController.ts`);
    }

    // Create middleware files (conditionally)
    console.log('\nCreating middleware files...');
    const errorHandlerPath = path.join(targetPath, 'middleware/errorHandler.ts');
    await fs.writeFile(errorHandlerPath, templates['middleware/errorHandler.ts']);
    console.log(`  ✓ Created file: middleware/errorHandler.ts`);
    
    if (options.includeAuth) {
      const verifyJWTPath = path.join(targetPath, 'middleware/verifyJWT.ts');
      let verifyJWTContent = templates['middleware/verifyJWT.ts'];
      
      // Update verifyJWT to conditionally include roles
      if (!options.includeRoleManagement) {
        // Remove roles from interface
        verifyJWTContent = verifyJWTContent.replace(
          /roles\?: \{[^}]+\};\n\s*/g,
          ''
        );
        // Update comment
        verifyJWTContent = verifyJWTContent.replace(
          /Adds userId and roles to request object if token is valid/,
          'Adds userId to request object if token is valid'
        );
        // Remove roles from decoded type and assignment
        verifyJWTContent = verifyJWTContent.replace(
          /roles: \{[^}]+\},\n\s*/g,
          ''
        );
        verifyJWTContent = verifyJWTContent.replace(
          /req\.roles = decoded\.roles;\n\s*/g,
          ''
        );
      }
      
      await fs.writeFile(verifyJWTPath, verifyJWTContent);
      console.log(`  ✓ Created file: middleware/verifyJWT.ts`);
      
      // Only create verifyRoles if role management is enabled
      if (options.includeRoleManagement) {
        const verifyRolesPath = path.join(targetPath, 'middleware/verifyRoles.ts');
        await fs.writeFile(verifyRolesPath, templates['middleware/verifyRoles.ts']);
        console.log(`  ✓ Created file: middleware/verifyRoles.ts`);
      }
    }
    
    if (options.rateLimit.enabled) {
      const rateLimiterPath = path.join(targetPath, 'middleware/rateLimiter.ts');
      let rateLimiterContent = templates['middleware/rateLimiter.ts'];
      
      // Replace placeholders with actual values
      rateLimiterContent = rateLimiterContent
        .replace('{{API_WINDOW_MS}}', options.rateLimit.apiWindowMs.toString())
        .replace('{{API_MAX}}', options.rateLimit.apiMax.toString())
        .replace('{{AUTH_WINDOW_MS}}', options.rateLimit.authWindowMs.toString())
        .replace('{{AUTH_MAX}}', options.rateLimit.authMax.toString());
      
      await fs.writeFile(rateLimiterPath, rateLimiterContent);
      console.log(`  ✓ Created file: middleware/rateLimiter.ts`);
    }

    // Create utility files
    console.log('\nCreating utility files...');
    const validateEnvPath = path.join(targetPath, 'utils/validateEnv.ts');
    let validateEnvContent = templates['utils/validateEnv.ts'];
    
    // Update validateEnv to conditionally require ACCESS_TOKEN_SECRET
    if (!options.includeAuth) {
      validateEnvContent = validateEnvContent.replace(
        "const requiredEnvVars = ['DB_URL', 'ACCESS_TOKEN_SECRET'];",
        "const requiredEnvVars = ['DB_URL'];"
      );
    }
    
    await fs.writeFile(validateEnvPath, validateEnvContent);
    console.log(`  ✓ Created file: utils/validateEnv.ts`);
    
    const paginationPath = path.join(targetPath, 'utils/pagination.ts');
    await fs.writeFile(paginationPath, templates['utils/pagination.ts']);
    console.log(`  ✓ Created file: utils/pagination.ts`);
    
    const validationPath = path.join(targetPath, 'utils/validation.ts');
    await fs.writeFile(validationPath, templates['utils/validation.ts']);
    console.log(`  ✓ Created file: utils/validation.ts`);

    // Conditionally create CI/CD files
    if (options.includeCI) {
      console.log('\nCreating CI/CD files...');
      
      // GitHub Actions
      const githubWorkflowsPath = path.join(targetPath, '.github/workflows');
      await fs.ensureDir(githubWorkflowsPath);
      const ciYmlPath = path.join(githubWorkflowsPath, 'ci.yml');
      await fs.writeFile(ciYmlPath, templates['.github/workflows/ci.yml']);
      console.log(`  ✓ Created file: .github/workflows/ci.yml`);
      
      // GitLab CI
      const gitlabCiPath = path.join(targetPath, '.gitlab-ci.yml');
      await fs.writeFile(gitlabCiPath, templates['.gitlab-ci.yml']);
      console.log(`  ✓ Created file: .gitlab-ci.yml`);
    }

    // Conditionally create test files
    if (options.includeTests) {
      console.log('\nCreating test files...');
      
      // Jest config
      const jestConfigPath = path.join(targetPath, 'jest.config.js');
      await fs.writeFile(jestConfigPath, templates['jest.config.js']);
      console.log(`  ✓ Created file: jest.config.js`);
      
      // Test setup
      const testsPath = path.join(targetPath, 'tests');
      await fs.ensureDir(testsPath);
      const setupPath = path.join(testsPath, 'setup.ts');
      await fs.writeFile(setupPath, templates['tests/setup.ts']);
      console.log(`  ✓ Created file: tests/setup.ts`);
      
      // Example test
      const authTestPath = path.join(testsPath, 'auth.test.ts');
      await fs.writeFile(authTestPath, templates['tests/auth.test.ts']);
      console.log(`  ✓ Created file: tests/auth.test.ts`);
      
      // Test environment file
      const envTestPath = path.join(targetPath, '.env.test');
      await fs.writeFile(envTestPath, templates['.env.test']);
      console.log(`  ✓ Created file: .env.test`);
      
      // Update package.json with test scripts and dependencies
      const packageJsonPath = path.join(targetPath, 'package.json');
      const packageJson = await fs.readJson(packageJsonPath);
      
      packageJson.scripts.test = 'jest';
      packageJson.scripts['test:watch'] = 'jest --watch';
      packageJson.scripts['test:coverage'] = 'jest --coverage';
      
      if (!packageJson.devDependencies) {
        packageJson.devDependencies = {};
      }
      packageJson.devDependencies['jest'] = '^29.7.0';
      packageJson.devDependencies['ts-jest'] = '^29.1.1';
      packageJson.devDependencies['@types/jest'] = '^29.5.11';
      packageJson.devDependencies['supertest'] = '^6.3.3';
      packageJson.devDependencies['@types/supertest'] = '^6.0.2';
      
      await fs.writeJson(packageJsonPath, packageJson, { spaces: 2 });
      console.log(`  ✓ Updated package.json with test dependencies`);
    }

    // Update package.json to conditionally include/remove dependencies
    const packageJsonPath = path.join(targetPath, 'package.json');
    const packageJson = await fs.readJson(packageJsonPath);
    
    if (!options.includeAuth) {
      // Remove auth-related dependencies
      delete packageJson.dependencies['bcryptjs'];
      delete packageJson.dependencies['jsonwebtoken'];
      delete packageJson.devDependencies['@types/bcryptjs'];
      delete packageJson.devDependencies['@types/jsonwebtoken'];
    }
    
    if (!options.includeSwagger) {
      // Remove Swagger dependencies
      delete packageJson.dependencies['swagger-jsdoc'];
      delete packageJson.dependencies['swagger-ui-express'];
      delete packageJson.devDependencies['@types/swagger-jsdoc'];
      delete packageJson.devDependencies['@types/swagger-ui-express'];
    }
    
    if (!options.rateLimit.enabled) {
      // Remove rate limiting dependency
      delete packageJson.dependencies['express-rate-limit'];
      delete packageJson.devDependencies['@types/express-rate-limit'];
    }
    
    if (!options.includeDocker) {
      // Remove Docker scripts
      delete packageJson.scripts['docker:build'];
      delete packageJson.scripts['docker:up'];
      delete packageJson.scripts['docker:down'];
      delete packageJson.scripts['docker:dev'];
    }
    
    await fs.writeJson(packageJsonPath, packageJson, { spaces: 2 });
    console.log(`  ✓ Updated package.json with conditional dependencies`);

    // Update .env.example to conditionally include ACCESS_TOKEN_SECRET
    if (!options.includeAuth) {
      const envExamplePath = path.join(targetPath, '.env.example');
      let envExampleContent = await fs.readFile(envExamplePath, 'utf-8');
      envExampleContent = envExampleContent.replace(
        /# Access Token Secret[\s\S]*?ACCESS_TOKEN_SECRET=.*\n/g,
        ''
      );
      await fs.writeFile(envExamplePath, envExampleContent);
    }

    console.log('\n✅ Backend structure generated successfully!');
    console.log(`\nNext steps:`);
    console.log(`  1. cd ${targetPath}`);
    console.log(`  2. npm install`);
    console.log(`  3. Update .env with your DB_URL${options.includeAuth ? ' and ACCESS_TOKEN_SECRET' : ''}`);
    console.log(`  4. npm run dev`);
  } catch (error) {
    console.error('Error generating backend structure:', error);
    process.exit(1);
  }
}

// Main execution
async function main(): Promise<void> {
const args = process.argv.slice(2);
const projectName = args[0] || 'backend-project';
const targetPath = path.resolve(process.cwd(), projectName);

  console.log(`\n🚀 Backend CLI - Express + TypeScript + MongoDB\n`);
  console.log(`Project name: ${projectName}`);
  console.log(`Target path: ${targetPath}\n`);

  // Prompt user for optional features
  const answers = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'includeAuth',
      message: 'Would you like to include authentication system (signup/login with JWT)?',
      default: true,
    },
    {
      type: 'confirm',
      name: 'includeRoleManagement',
      message: 'Would you like to include role-based access control (RBAC) with verifyRoles middleware?',
      default: false,
      when: (answers) => answers.includeAuth, // Only show if auth is enabled
    },
    {
      type: 'confirm',
      name: 'includeSwagger',
      message: 'Would you like to include Swagger API documentation?',
      default: true,
    },
    {
      type: 'confirm',
      name: 'includeDocker',
      message: 'Would you like to include Docker configuration files?',
      default: true,
    },
    {
      type: 'confirm',
      name: 'includeRateLimit',
      message: 'Would you like to include rate limiting?',
      default: true,
    },
    {
      type: 'confirm',
      name: 'useDefaultRateLimit',
      message: 'Use default rate limiting settings?',
      default: true,
      when: (answers) => answers.includeRateLimit,
    },
    {
      type: 'input',
      name: 'apiWindowMs',
      message: 'API rate limit window (minutes):',
      default: '15',
      validate: (input) => !isNaN(parseInt(input)) || 'Please enter a valid number',
      when: (answers) => answers.includeRateLimit && !answers.useDefaultRateLimit,
    },
    {
      type: 'input',
      name: 'apiMax',
      message: 'API rate limit max requests per window:',
      default: '100',
      validate: (input) => !isNaN(parseInt(input)) || 'Please enter a valid number',
      when: (answers) => answers.includeRateLimit && !answers.useDefaultRateLimit,
    },
    {
      type: 'input',
      name: 'authWindowMs',
      message: 'Auth rate limit window (minutes):',
      default: '15',
      validate: (input) => !isNaN(parseInt(input)) || 'Please enter a valid number',
      when: (answers) => answers.includeRateLimit && !answers.useDefaultRateLimit,
    },
    {
      type: 'input',
      name: 'authMax',
      message: 'Auth rate limit max requests per window:',
      default: '5',
      validate: (input) => !isNaN(parseInt(input)) || 'Please enter a valid number',
      when: (answers) => answers.includeRateLimit && !answers.useDefaultRateLimit,
    },
    {
      type: 'confirm',
      name: 'includeCI',
      message: 'Would you like to include CI/CD templates (GitHub Actions & GitLab CI)?',
      default: false,
    },
    {
      type: 'confirm',
      name: 'includeTests',
      message: 'Would you like to include Jest testing setup?',
      default: false,
    },
    {
      type: 'confirm',
      name: 'includeHealthCheck',
      message: 'Would you like to include a health check endpoint (/health)?',
      default: true,
    },
  ]);

  // Set rate limit config
  const rateLimitConfig: RateLimitConfig = {
    enabled: answers.includeRateLimit,
    apiWindowMs: answers.includeRateLimit && answers.useDefaultRateLimit 
      ? 15 * 60 * 1000 
      : answers.includeRateLimit 
        ? parseInt(answers.apiWindowMs) * 60 * 1000 
        : 15 * 60 * 1000,
    apiMax: answers.includeRateLimit && answers.useDefaultRateLimit 
      ? 100 
      : answers.includeRateLimit 
        ? parseInt(answers.apiMax) 
        : 100,
    authWindowMs: answers.includeRateLimit && answers.useDefaultRateLimit 
      ? 15 * 60 * 1000 
      : answers.includeRateLimit 
        ? parseInt(answers.authWindowMs) * 60 * 1000 
        : 15 * 60 * 1000,
    authMax: answers.includeRateLimit && answers.useDefaultRateLimit 
      ? 5 
      : answers.includeRateLimit 
        ? parseInt(answers.authMax) 
        : 5,
  };

  console.log(`\nGenerating backend structure...\n`);
  
  await generateBackendStructure(targetPath, {
    includeAuth: answers.includeAuth,
    includeRoleManagement: answers.includeRoleManagement || false,
    includeSwagger: answers.includeSwagger,
    includeDocker: answers.includeDocker,
    rateLimit: rateLimitConfig,
    includeCI: answers.includeCI,
    includeTests: answers.includeTests,
    includeHealthCheck: answers.includeHealthCheck,
  });
}

main().catch((error) => {
  console.error('Error:', error);
  process.exit(1);
});
