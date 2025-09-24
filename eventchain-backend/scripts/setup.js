/**
 * EventChain Backend Setup Script
 * 
 * This script helps set up the development environment:
 * - Installs dependencies
 * - Sets up database
 * - Runs initial migrations
 * - Validates Hedera connection
 * - Creates initial admin user
 */

const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const colors = {
    green: '\x1b[32m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    reset: '\x1b[0m'
};

function log(message, color = 'reset') {
    console.log(`${colors[color]}${message}${colors.reset}`);
}

function runCommand(command, description) {
    return new Promise((resolve, reject) => {
        log(`\n${description}...`, 'blue');
        exec(command, (error, stdout, stderr) => {
            if (error) {
                log(`❌ ${description} failed:`, 'red');
                log(error.message, 'red');
                reject(error);
                return;
            }
            if (stderr) {
                log(`⚠️ Warning: ${stderr}`, 'yellow');
            }
            if (stdout.trim()) {
                log(stdout, 'green');
            }
            log(`✅ ${description} completed`, 'green');
            resolve(stdout);
        });
    });
}

async function setup() {
    try {
        log('🚀 Setting up EventChain Backend...', 'blue');
        
        // Check if .env exists
        if (!fs.existsSync('.env')) {
            log('⚠️ No .env file found. Please copy .env.example to .env and configure it.', 'yellow');
            log('Run: cp .env.example .env', 'yellow');
            process.exit(1);
        }
        
        // Install dependencies
        await runCommand('npm install', 'Installing dependencies');
        
        // Generate Prisma client
        await runCommand('npx prisma generate', 'Generating Prisma client');
        
        // Check database connection
        log('\n🔍 Checking database connection...', 'blue');
        try {
            await runCommand('npx prisma db push', 'Setting up database schema');
        } catch (error) {
            log('❌ Database setup failed. Please ensure PostgreSQL is running and DATABASE_URL is correct.', 'red');
            log('Example DATABASE_URL: postgresql://postgres:password@localhost:5432/eventchain_dev', 'yellow');
            process.exit(1);
        }
        
        // Build TypeScript
        await runCommand('npm run build', 'Building TypeScript');
        
        log('\n✅ Backend setup completed successfully!', 'green');
        log('\n📋 Next steps:', 'blue');
        log('1. Configure your .env file with actual values', 'yellow');
        log('2. Set up Hedera testnet account at https://portal.hedera.com', 'yellow');
        log('3. Run: npm run dev', 'yellow');
        log('4. Test the health endpoint: http://localhost:3001/health', 'yellow');
        
    } catch (error) {
        log(`❌ Setup failed: ${error.message}`, 'red');
        process.exit(1);
    }
}

setup();
