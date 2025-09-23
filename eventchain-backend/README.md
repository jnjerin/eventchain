# EventChain Backend

Web3 ticketing platform backend built with Node.js, Express, TypeScript, and Hedera Hashgraph.

## 🏗️ Architecture

- **Framework**: Express.js + TypeScript
- **Database**: PostgreSQL + Prisma ORM
- **Blockchain**: Hedera Hashgraph for NFT tickets & loyalty tokens
- **Authentication**: JWT with role-based access control
- **Caching**: Redis for sessions and performance
- **Logging**: Winston for structured logging

## 🚀 Quick Start

### Prerequisites

- Node.js 18+ and npm
- PostgreSQL 14+
- Redis (optional, for production caching)
- Hedera testnet account

### Setup

1. **Install dependencies and setup database**:
   ```bash
   node scripts/setup.js
   ```

2. **Configure environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your actual values
   ```

3. **Run development server**:
   ```bash
   npm run dev
   ```

4. **Test the setup**:
   ```bash
   curl http://localhost:3001/health
   ```

## 📚 API Documentation

### Base URL
```
http://localhost:3001/api/v1
```

### Authentication
All protected routes require a Bearer token in the Authorization header:
```
Authorization: Bearer <your-jwt-token>
```

### Endpoints

#### Authentication
- `POST /auth/register` - Register new user
- `POST /auth/login` - User login
- `POST /auth/logout` - User logout

#### Events
- `GET /events` - List all events
- `POST /events` - Create new event (Organizer+)
- `GET /events/:id` - Get event details
- `PUT /events/:id` - Update event (Owner/Admin)

#### Tickets
- `POST /tickets/mint` - Mint NFT tickets (Organizer+)
- `GET /tickets/:id` - Get ticket details
- `POST /tickets/validate` - Validate ticket at gate (Staff+)
- `POST /tickets/transfer` - Transfer ticket ownership

#### Loyalty
- `GET /loyalty/:userId` - Get user loyalty balance
- `POST /loyalty/earn` - Award loyalty points
- `POST /loyalty/redeem` - Redeem loyalty points

#### SMS Affiliates
- `POST /sms/send` - Send SMS campaign (Affiliate+)
- `GET /sms/stats/:affiliateId` - Get affiliate statistics

## 🔧 Development Commands

```bash
# Development server with hot reload
npm run dev

# Build TypeScript
npm run build

# Run production server
npm start

# Database operations
npm run migrate      # Run migrations
npm run db:push      # Push schema changes
npm run db:studio    # Open Prisma Studio

# Testing
npm test
npm run test:watch

# Code quality
npm run lint
npm run lint:fix
```

## 🗃️ Database Schema

### Key Models

- **User**: Authentication, roles (USER, ORGANIZER, AFFILIATE, STAFF, ADMIN)
- **Event**: Event details, timing, capacity
- **TicketType**: Different ticket categories per event
- **Ticket**: NFT tickets with Hedera references
- **LoyaltyTransaction**: Loyalty points earning/redemption
- **Session**: JWT session management

### Relationships

```
User (1) -> (*) Event (organizer)
Event (1) -> (*) TicketType
TicketType (1) -> (*) Ticket
User (1) -> (*) Ticket (owner)
User (1) -> (*) LoyaltyTransaction
```

## 🔐 Security Features

- **JWT Authentication**: Stateless token-based auth
- **Role-based Access Control**: Hierarchical permissions
- **Input Validation**: Joi schema validation
- **Rate Limiting**: Prevent API abuse
- **SQL Injection Protection**: Prisma ORM parameterized queries
- **CORS Configuration**: Cross-origin request control
- **Helmet.js**: Security headers

## 🌐 Hedera Integration

### NFT Tickets
- Each event creates an NFT collection
- Individual tickets are unique NFTs within the collection
- QR codes link database records to blockchain ownership
- Real-time ownership verification for gate scanning

### Loyalty Tokens
- Fungible tokens representing loyalty points
- Earned through ticket purchases and referrals
- Redeemable for discounts and rewards
- Transparent on-chain tracking

### Cost Efficiency
- ~$0.001 per transaction vs $10-50 on Ethereum
- 3-5 second finality vs 15+ minutes
- Predictable fees for business planning

## 📊 Monitoring & Logging

### Structured Logging
- Request/response tracking
- Error stack traces
- Performance metrics
- Business event tracking

### Health Checks
- Database connectivity
- Hedera network status
- Redis connection (if configured)
- Service dependencies

## 🧪 Testing

### Test Structure
```
tests/
├── unit/          # Unit tests for individual functions
├── integration/   # API endpoint tests
└── e2e/          # End-to-end workflow tests
```

### Running Tests
```bash
# All tests
npm test

# Watch mode for development
npm run test:watch

# Coverage report
npm run test:coverage
```

## 🚀 Deployment

### Environment Variables
See `.env.example` for all required configuration.

### Production Checklist
- [ ] Set strong JWT_SECRET
- [ ] Configure production database
- [ ] Set up Hedera mainnet account
- [ ] Configure Redis for caching
- [ ] Set up error monitoring (Sentry)
- [ ] Configure SSL certificates
- [ ] Set up log aggregation
- [ ] Configure backup strategy

### Docker Deployment
```bash
# Build image
docker build -t eventchain-backend .

# Run container
docker run -p 3001:3001 --env-file .env eventchain-backend
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Troubleshooting

### Common Issues

#### Database Connection Errors
```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Test connection
psql -h localhost -p 5432 -U postgres -d eventchain_dev
```

#### Hedera Connection Issues
- Verify account ID and private key in .env
- Check network (testnet vs mainnet)
- Ensure account has sufficient HBAR balance

#### TypeScript Errors
```bash
# Regenerate Prisma client
npx prisma generate

# Clear TypeScript cache
rm -rf node_modules/.cache
```

### Support
- 📧 Email: support@eventchain.com
- 💬 Discord: [EventChain Community](https://discord.gg/eventchain)
- 🐛 Issues: [GitHub Issues](https://github.com/eventchain/backend/issues)
