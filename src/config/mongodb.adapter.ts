import { Adapter, AdapterPayload } from 'oidc-provider';
import { Collection, Db, ObjectId, Document as MongoDocument } from 'mongodb';
import { getDb } from './database';
import logger from './middlewares/logger';

const getCollection = <T extends MongoDocument = MongoDocument>(name: string): Collection<T> => {
    const db = getDb();
    if (!db) {
        throw new Error('MongoDB connection not established or DB instance not available.');
    }
    const collectionName = name.toLowerCase();
    logger.debug(`[MongoAdapter] Accessing collection: ${collectionName}`);
    // Return collection typed with T
    return db.collection<T>(collectionName);
};
interface StoredPayload extends AdapterPayload {
    _id?: ObjectId;
    oidcId: string;
    expiresAt?: Date;
    consumed?: number; // Timestamp when consumed
    uid?: string;
    userCode?: string;
    grantId?: string;
}

class MongoDbAdapter implements Adapter {
    constructor(public name: string) {}

        // Get the MongoDB collection specifically typed for StoredPayload
    private get collection(): Collection<StoredPayload> {
        const collectionName = `${this.name.toLowerCase()}s`;
        // Call the generic helper, providing the specific type argument
        return getCollection<StoredPayload>(collectionName);
    }

    /**
     * Upserts an OIDC artifact. Stores the provider's 'id' in 'oidcId' field.
     */
    async upsert(id: string, payload: AdapterPayload, expiresIn: number): Promise<void> {
        let expiresAt: Date | undefined;
        if (expiresIn) {
            expiresAt = new Date(Date.now() + expiresIn * 1000);
        }
    
        const filter = { oidcId: id }; // Use your custom ID field
        const documentToSet = { ...payload, oidcId: id, ...(expiresAt && { expiresAt }) };
    
        // Log based on payload kind if desired
        if (payload.kind === 'Grant') {
            logger.debug(`[MongoAdapter:upsert:Grant] Attempting to save grant for accountId: ${payload.accountId}, clientId: ${payload.clientId}`);
            // logger.debug(`[MongoAdapter:upsert:Grant] Grant payload:`, payload); // Log payload if needed
        } else {
             logger.debug(`[MongoAdapter:${this.name}] Upserting document kind: ${payload.kind} with id: ${id}`);
        }
    
        try {
            const result = await this.collection.updateOne(
                filter,
                { $set: documentToSet },
                { upsert: true }
            );
    
            // Log success confirmation
            if (payload.kind === 'Grant') {
                logger.debug(`[MongoAdapter:upsert:Grant] MongoDB updateOne completed for id: ${id}`, {
                    matchedCount: result.matchedCount,
                    modifiedCount: result.modifiedCount,
                    upsertedCount: result.upsertedCount,
                    upsertedId: result.upsertedId
                });
            }
            // **** DO NOT return anything here ****
    
        } catch (error) {
             logger.error(`[MongoAdapter:upsert] Error saving ${payload.kind} with id ${id}:`, error);
             throw error; // Re-throw error so provider knows it failed
        }
    }

    /**
     * Finds an OIDC artifact by its provider ID ('oidcId').
     * Returns undefined if expired or already consumed.
     */
    async find(id: string): Promise<AdapterPayload | undefined> {
        logger.debug(`[MongoAdapter:find] Searching for document with oidcId: ${id}`); // Log find attempt
        const result = await this.collection.findOne({ oidcId: id });
        if (!result) {
            logger.warn(`[MongoAdapter:find] Document not found for oidcId: ${id}`); // Log if not found
            return undefined;
       }

        // Check expiration
        if (result.expiresAt && result.expiresAt < new Date()) {
            await this.destroy(id);
            return undefined;
        }

        // *** ADDED CHECK: Return undefined if already consumed ***
        if (result.consumed) {
            logger.debug(`[MongoAdapter:${this.name}] Find - Already Consumed: ${id}`);
            // Optionally delete consumed codes after a short grace period? For now, just don't return it.
            // await this.destroy(id);
            return undefined;
        }

        const { _id, oidcId, ...payload } = result;
        logger.debug(`[MongoAdapter:find] Found document for oidcId: ${id}`);
        return payload as AdapterPayload;
    }

    async findByUid(uid: string): Promise<AdapterPayload | undefined> {
         const result = await this.collection.findOne({ uid });
         if (!result) return undefined;
         if (result.expiresAt && result.expiresAt < new Date()) {
             await this.destroy(result.oidcId);
             return undefined;
         }
         // *** ADDED CHECK: Return undefined if already consumed (relevant for Session?) ***
         if (result.consumed) {
             logger.debug(`[MongoAdapter:${this.name}] FindByUid - Already Consumed: ${uid}`);
             return undefined;
         }
         const { _id, oidcId, ...payload } = result;
         return payload as AdapterPayload;
    }

    async findByUserCode(userCode: string): Promise<AdapterPayload | undefined> {
         const result = await this.collection.findOne({ userCode });
         if (!result) return undefined;
         if (result.expiresAt && result.expiresAt < new Date()) {
             await this.destroy(result.oidcId);
             return undefined;
         }
          // *** ADDED CHECK: Return undefined if already consumed (relevant for DeviceCode?) ***
         if (result.consumed) {
             logger.debug(`[MongoAdapter:${this.name}] FindByUserCode - Already Consumed: ${userCode}`);
             return undefined;
         }
         const { _id, oidcId, ...payload } = result;
         return payload as AdapterPayload;
    }

    /**
     * Destroys an OIDC artifact by its provider ID ('oidcId').
     */
    async destroy(id: string): Promise<void> {
        logger.debug(`[MongoAdapter:destroy] Deleting document with oidcId: ${id}`); // ADD LOG
        // Delete using the dedicated 'oidcId' field.
        await this.collection.deleteOne({ oidcId: id });
    }

    /**
     * Revokes OIDC artifacts associated with a specific grantId.
     */
    async revokeByGrantId(grantId: string): Promise<void> {
        // This logic remains the same - delete based on the 'grantId' field.
        const modelsToRevoke = ['AccessToken', 'AuthorizationCode', 'RefreshToken', 'DeviceCode', 'BackchannelAuthenticationRequest'];
        logger.debug(`[MongoAdapter] Revoking by Grant ID: ${grantId}`);
        for (const modelName of modelsToRevoke) {
             try {
                 // Need to get collection using lowercase name convention
                 const coll = getCollection(`${modelName.toLowerCase()}s`);
                 const result = await coll.deleteMany({ grantId });
                 if (result.deletedCount > 0) {
                     logger.debug(`[MongoAdapter:${modelName}] Revoked ${result.deletedCount} items for Grant ID: ${grantId}`);
                 }
             } catch (error) {
                  logger.error(`[MongoAdapter] Error revoking ${modelName} for grantId ${grantId}:`, error);
             }
        }
    }
    /**
     * Marks an OIDC artifact as consumed by setting the 'consumed' timestamp.
     */
    async consume(id: string): Promise<void> {
        logger.debug(`[MongoAdapter:consume] Marking document consumed for oidcId: ${id}`); // ADD LOG
        // Update using the dedicated 'oidcId' field.
        const result = await this.collection.updateOne(
            { oidcId: id },
            // Ensure the consumed field exists and is only set once
            // { $currentDate: { consumed: { $type: 'timestamp' } } }
            { $set: { consumed: Math.floor(Date.now() / 1000) } }
        );
         if (result.modifiedCount === 1) { logger.debug(`[MongoAdapter:${this.name}] Consumed ID: ${id}`); }
    }
}

export default function adapterFactory(name: string): Adapter {
    return new MongoDbAdapter(name);
}