/**
 * Hedera Hashgraph Configuration and Client Setup
 * 
 * This module handles connection to Hedera Hashgraph network for:
 * - NFT ticket minting and management
 * - Fungible loyalty token operations
 * - Transaction verification and status checking
 * 
 * Hedera Benefits for Our Use Case:
 * - Low fees ($0.001 per transaction)
 * - Fast finality (3-5 seconds)
 * - Environmental sustainability (carbon-negative)
 * - Enterprise-grade security and consensus
 */

import {
    Client,
    PrivateKey,
    AccountId,
    Hbar,
    TokenCreateTransaction,
    TokenType,
    TokenSupplyType,
    TokenMintTransaction,
    TokenAssociateTransaction,
    TransferTransaction,
    TokenNftInfoQuery,
    AccountBalanceQuery,
    TransactionReceiptQuery,
    Status,
    PublicKey
} from '@hashgraph/sdk';

import { logger } from './logger';

/**
 * Hedera client instance
 * Singleton pattern to avoid multiple network connections
 */
let hederaClient: Client | null = null;

/**
 * Account credentials for Hedera operations
 */
interface HederaCredentials {
    accountId: AccountId;
    privateKey: PrivateKey;
    publicKey: PublicKey;
}

/**
 * Treasury account (receives platform fees)
 */
let treasuryAccount: HederaCredentials;

/**
 * Operator account (performs transactions)
 */
let operatorAccount: HederaCredentials;

/**
 * Initialize Hedera client with environment credentials
 * 
 * @returns Configured Hedera client
 */
export function initializeHederaClient(): Client {
    try {
        // Don't reinitialize if client already exists
        if (hederaClient) {
            return hederaClient;
        }

        // Validate required environment variables
        const requiredEnvVars = [
            'HEDERA_NETWORK',
            'HEDERA_ACCOUNT_ID',
            'HEDERA_PRIVATE_KEY'
        ];

        for (const envVar of requiredEnvVars) {
            if (!process.env[envVar]) {
                throw new Error(`Missing required environment variable: ${envVar}`);
            }
        }

        // Parse network configuration
        const network = process.env.HEDERA_NETWORK!.toLowerCase();
        
        // Create client based on network
        if (network === 'testnet') {
            hederaClient = Client.forTestnet();
        } else if (network === 'mainnet') {
            hederaClient = Client.forMainnet();
        } else {
            throw new Error(`Unsupported Hedera network: ${network}`);
        }

        // Set up operator account (account that signs and pays for transactions)
        const accountId = AccountId.fromString(process.env.HEDERA_ACCOUNT_ID!);
        const privateKey = PrivateKey.fromString(process.env.HEDERA_PRIVATE_KEY!);
        const publicKey = privateKey.publicKey;

        hederaClient.setOperator(accountId, privateKey);

        // Store operator credentials
        operatorAccount = {
            accountId,
            privateKey,
            publicKey
        };

        // Set up treasury account (can be same as operator for development)
        const treasuryId = process.env.HEDERA_TREASURY_ID 
            ? AccountId.fromString(process.env.HEDERA_TREASURY_ID)
            : accountId;
        const treasuryKey = process.env.HEDERA_TREASURY_KEY
            ? PrivateKey.fromString(process.env.HEDERA_TREASURY_KEY)
            : privateKey;

        treasuryAccount = {
            accountId: treasuryId,
            privateKey: treasuryKey,
            publicKey: treasuryKey.publicKey
        };

        logger.info('✅ Hedera client initialized successfully', {
            network,
            operatorAccount: accountId.toString(),
            treasuryAccount: treasuryId.toString()
        });

        return hederaClient;

    } catch (error) {
        logger.error('❌ Failed to initialize Hedera client:', error);
        throw new Error(`Hedera initialization failed: ${error instanceof Error ? error.message : error}`);
    }
}

/**
 * Get the current Hedera client instance
 * 
 * @returns Active Hedera client
 */
export function getHederaClient(): Client {
    if (!hederaClient) {
        return initializeHederaClient();
    }
    return hederaClient;
}

/**
 * Get operator account credentials
 * 
 * @returns Operator account details
 */
export function getOperatorAccount(): HederaCredentials {
    if (!operatorAccount) {
        initializeHederaClient();
    }
    return operatorAccount;
}

/**
 * Get treasury account credentials
 * 
 * @returns Treasury account details
 */
export function getTreasuryAccount(): HederaCredentials {
    if (!treasuryAccount) {
        initializeHederaClient();
    }
    return treasuryAccount;
}

/**
 * Check Hedera network connectivity and account balance
 * 
 * @returns Network status and account info
 */
export async function checkHederaHealth(): Promise<{
    status: 'healthy' | 'unhealthy';
    network?: string;
    accountBalance?: string;
    error?: string;
}> {
    try {
        const client = getHederaClient();
        const operatorId = getOperatorAccount().accountId;

        // Query account balance to test connectivity
        const balance = await new AccountBalanceQuery()
            .setAccountId(operatorId)
            .execute(client);

        return {
            status: 'healthy',
            network: process.env.HEDERA_NETWORK,
            accountBalance: balance.hbars.toString()
        };

    } catch (error) {
        logger.error('Hedera health check failed:', error);
        return {
            status: 'unhealthy',
            error: error instanceof Error ? error.message : 'Unknown Hedera error'
        };
    }
}

/**
 * Create a new NFT collection for event tickets
 * Each event gets its own NFT token type
 * 
 * @param eventTitle - Name of the event
 * @param eventDescription - Description of the event  
 * @param maxSupply - Maximum number of tickets
 * @returns Token ID of created NFT collection
 */
export async function createEventNftCollection(
    eventTitle: string,
    eventDescription: string,
    maxSupply: number
): Promise<string> {
    try {
        const client = getHederaClient();
        const treasury = getTreasuryAccount();

        logger.info('Creating NFT collection for event', {
            eventTitle,
            maxSupply
        });

        // Create the NFT token
        const createTokenTx = new TokenCreateTransaction()
            .setTokenName(`EventChain: ${eventTitle}`)
            .setTokenSymbol('EVTKT')
            .setTokenType(TokenType.NonFungibleUnique)
            .setSupplyType(TokenSupplyType.Finite)
            .setInitialSupply(0) // NFTs start with 0 supply
            .setMaxSupply(maxSupply)
            .setTreasuryAccountId(treasury.accountId)
            .setSupplyKey(treasury.privateKey) // Allows minting new NFTs
            .setAdminKey(treasury.privateKey)  // Allows token management
            .setTokenMemo(eventDescription.substring(0, 100)) // Hedera memo limit
            .freezeWith(client);

        // Sign and execute transaction
        const signedTx = await createTokenTx.sign(treasury.privateKey);
        const txResponse = await signedTx.execute(client);

        // Get the receipt to confirm success
        const receipt = await txResponse.getReceipt(client);
        
        if (receipt.status !== Status.Success) {
            throw new Error(`Token creation failed with status: ${receipt.status}`);
        }

        const tokenId = receipt.tokenId!.toString();

        logger.info('✅ NFT collection created successfully', {
            eventTitle,
            tokenId,
            transactionId: txResponse.transactionId.toString()
        });

        return tokenId;

    } catch (error) {
        logger.error('❌ Failed to create NFT collection:', error);
        throw new Error(`NFT collection creation failed: ${error instanceof Error ? error.message : error}`);
    }
}

/**
 * Clean up Hedera client connection
 * Call this during application shutdown
 */
export async function closeHederaClient(): Promise<void> {
    try {
        if (hederaClient) {
            await hederaClient.close();
            hederaClient = null;
            logger.info('✅ Hedera client connection closed');
        }
    } catch (error) {
        logger.error('❌ Error closing Hedera client:', error);
    }
}

// Export types for use in other modules
export type { HederaCredentials };
