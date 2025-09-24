# KAM Assessment Portal Backend

A robust, multi-tenant Node.js backend API for the Key Account Manager (KAM) Assessment Portal. Built with TypeScript, Express, PostgreSQL, and comprehensive security features.

## 🚀 Features

- **Multi-Tenant Architecture**: Complete tenant isolation with domain-based routing
- **Secure Authentication**: JWT-based auth with refresh tokens and rate limiting
- **Database Management**: PostgreSQL with migrations, seeding, and connection pooling
- **Comprehensive Security**: Helmet, CORS, rate limiting, input validation
- **Structured Logging**: Winston-based logging with multiple log levels and files
- **Error Handling**: Custom error classes with proper HTTP status codes
- **Performance Optimized**: Compression, caching strategies, and database indexing
- **Development Ready**: Hot reload, linting, testing setup

## 📋 Prerequisites

- Node.js 18+ 
- PostgreSQL 15+
- Yarn package manager
- Neon Database (or local PostgreSQL)

## 🛠️ Installation

1. **Clone and install dependencies**
   ```bash
   git clone <repository-url>
   cd kamsprojs
   yarn install
   ```

2. **Environment Configuration**
   
   Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
   
   Update `.env` with your configuration:
   ```env
   # Database - Update with your Neon DB connection string
   DATABASE_URL=postgresql://username:password@host:5432/database_name
   
   # JWT Secret - Generate a secure random string
   JWT_SECRET=your-super-secure-jwt-secret-key
   
   # Other configurations as needed
   ```

3. **Database Setup**
   
   Run migrations to create the database schema:
   ```bash
   yarn migrate
   ```
   
   Seed the database with sample data:
   ```bash
   yarn seed
   ```

4. **Start the development server**
   ```bash
   yarn dev
   ```

The server will start at `http://localhost:3000`

## 🗄️ Database Configuration

### Using Neon Database

1. Create account at [Neon](https://neon.tech/)
2. Create a new project
3. Use the development branch for testing
4. Use the production branch for production
5. Copy the connection string to your `.env` file

### Local PostgreSQL Setup

If using local PostgreSQL:

```bash
# Install PostgreSQL
# Create database
createdb kam_dev

# Update DATABASE_URL in .env
DATABASE_URL=postgresql://username:password@localhost:5432/kam_dev
```

## 📚 Available Scripts

```bash
# Development
yarn dev              # Start development server with hot reload
yarn build            # Build for production
yarn start            # Start production server

# Database
yarn migrate          # Run database migrations
yarn migrate:rollback # Rollback last migration
yarn seed             # Seed database with sample data
yarn db:reset         # Reset and reseed database

# Code Quality
yarn lint             # Run ESLint
yarn lint:fix         # Fix ESLint errors
yarn format           # Format code with Prettier

# Testing
yarn test             # Run tests
yarn test:watch       # Run tests in watch mode
yarn test:coverage    # Run tests with coverage
```

## 🏗️ Architecture

### Multi-Tenant Design

The system uses a **multi-tenant architecture** with complete data isolation:

- **Domain-based routing**: Each tenant has a unique domain/subdomain
- **Database isolation**: All queries are automatically scoped by `tenant_id`
- **Middleware-enforced**: Tenant context is enforced at the middleware level
- **Security-first**: No cross-tenant data access possible

### Folder Structure

```
src/
├── config/           # Configuration management
├── controllers/      # Request handlers
├── database/         # Database connection, migrations, seeds
│   ├── migrations/   # SQL migration files
│   └── seeds/        # Database seeding
├── middleware/       # Express middleware
├── models/           # Data models and database queries
├── routes/           # API route definitions  
├── services/         # Business logic services
├── types/            # TypeScript type definitions
└── utils/            # Utility functions and helpers
```

## 🛡️ Security Features

### Authentication & Authorization
- JWT tokens with refresh token rotation
- bcrypt password hashing (12 rounds)
- Rate limiting on auth endpoints
- Account lockout after failed attempts

### Request Security
- Helmet.js for security headers
- CORS configuration
- Request size limits
- Input validation with Zod
- SQL injection prevention

### Tenant Isolation
- Row-level security (RLS) in database
- Middleware-enforced tenant context
- Domain validation
- Query-level tenant filtering

## 📊 API Endpoints

### Health & Status
- `GET /health` - Application health check
- `GET /health/db` - Database health check
- `GET /api` - API information

### Authentication (Planned)
- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/logout` - User logout
- `POST /api/v1/auth/refresh` - Refresh access token

### Users (Planned)
- `GET /api/v1/users` - List users
- `POST /api/v1/users` - Create user
- `GET /api/v1/users/:id` - Get user
- `PUT /api/v1/users/:id` - Update user
- `DELETE /api/v1/users/:id` - Delete user

### Assessments (Planned)
- `GET /api/v1/assessments` - List assessments
- `POST /api/v1/assessments` - Create assessment
- `GET /api/v1/assessments/:id` - Get assessment
- `PUT /api/v1/assessments/:id` - Update assessment
- `POST /api/v1/assessments/:id/submit` - Submit assessment

## 🔧 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_ENV` | Environment (development/production) | development |
| `PORT` | Server port | 3000 |
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `JWT_SECRET` | JWT signing secret | Required |
| `JWT_EXPIRES_IN` | Access token expiry | 15m |
| `BCRYPT_ROUNDS` | Password hashing rounds | 12 |
| `LOG_LEVEL` | Logging level | info |

## 📝 Logging

The application uses structured logging with Winston:

- **Combined logs**: All application logs
- **Error logs**: Error-level logs only  
- **Request logs**: HTTP request logging
- **Security logs**: Authentication/authorization events
- **Audit logs**: User actions and data changes
- **Performance logs**: Slow queries and operations

Log files are stored in the `logs/` directory (configurable via `LOG_DIR`).

## 🧪 Testing

Testing setup is configured with Jest and Supertest:

```bash
# Run all tests
yarn test

# Run tests in watch mode  
yarn test:watch

# Run with coverage
yarn test:coverage
```

## 🚀 Deployment

### Production Build
```bash
yarn build
yarn start:prod
```

### Docker (Optional)
```dockerfile
# Create Dockerfile based on the Node.js Alpine image
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN yarn install --production
COPY dist ./dist
EXPOSE 3000
CMD ["node", "dist/index.js"]
```

## 🔄 Database Migrations

### Creating Migrations

Create a new migration file in `src/database/migrations/`:

```sql
-- UP
CREATE TABLE example_table (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL
);

-- DOWN  
DROP TABLE IF EXISTS example_table;
```

Migration files must:
- Be named with format: `001_description.sql`
- Include both `-- UP` and `-- DOWN` sections
- Use proper PostgreSQL syntax

### Running Migrations

```bash
# Run pending migrations
yarn migrate

# Rollback last migration
yarn migrate:rollback

# Check migration status
yarn migrate status
```

## 🌱 Database Seeding

The seeder creates sample data for development:

- **2 Sample tenants** with different subscription tiers
- **Admin users** for each tenant
- **Sample users** with different roles
- **Default assessment questions**
- **Tenant settings** and configurations

```bash
# Seed database
yarn seed

# Reset and reseed
yarn db:reset
```

## 🚨 Error Handling

The application includes comprehensive error handling:

```typescript
// Custom error classes
throw new ValidationError('Invalid input data');
throw new AuthenticationError('Invalid credentials');
throw new AuthorizationError('Insufficient permissions');
throw new NotFoundError('Resource not found');
```

Errors are automatically logged and return structured JSON responses.

## 📈 Performance Considerations

- **Connection pooling**: PostgreSQL connection pool (configurable size)
- **Database indexing**: Optimized indexes for multi-tenant queries
- **Compression**: Gzip compression for responses
- **Rate limiting**: Prevent API abuse
- **Caching**: Ready for Redis integration
- **Query optimization**: Efficient database queries with tenant isolation

## 🔒 Multi-Tenant Security

The application ensures complete tenant isolation through multiple layers:

1. **Middleware-level**: Tenant context extraction and validation
2. **Database-level**: Row-level security and tenant-scoped queries  
3. **Application-level**: Service layer tenant filtering
4. **URL-level**: Domain-based tenant identification

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📋 Development Workflow

1. **Setup**: Follow installation instructions
2. **Database**: Run migrations and seed data
3. **Development**: Use `yarn dev` for hot reload
4. **Testing**: Write tests for new features
5. **Linting**: Ensure code quality with `yarn lint`
6. **Documentation**: Update API documentation

## 🛡️ Security Checklist

- [ ] Environment variables secured
- [ ] Database credentials protected
- [ ] JWT secrets are strong and rotated
- [ ] Rate limiting configured
- [ ] Input validation implemented
- [ ] SQL injection prevention verified
- [ ] Tenant isolation tested
- [ ] Audit logging enabled

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🆘 Troubleshooting

### Common Issues

**Database Connection Error**
- Verify DATABASE_URL in `.env`
- Check network connectivity to database
- Ensure database exists and credentials are correct

**Migration Failures**
- Check database permissions
- Verify migration file format
- Review error logs in `logs/error.log`

**Port Already in Use**
- Change PORT in `.env` file
- Kill existing processes: `lsof -ti:3000 | xargs kill -9`

**Build Errors**
- Clear TypeScript cache: `yarn build --clean`
- Reinstall dependencies: `rm -rf node_modules && yarn install`

### Getting Help

1. Check the logs in `logs/` directory
2. Review error messages carefully
3. Verify environment configuration
4. Test database connectivity independently

---

**Version**: 1.0.0  
**Last Updated**: 2025-01-16  
**Node.js**: 18+  
**Database**: PostgreSQL 15+