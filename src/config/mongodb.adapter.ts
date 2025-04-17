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

        // Use 'oidcId' field for querying and explicitly set it in the update.
        // Let MongoDB handle the internal '_id' (ObjectId).
        await this.collection.updateOne(
            { oidcId: id }, // Query using the dedicated field
            { $set: { ...payload, oidcId: id, ...(expiresAt && { expiresAt }) } }, // Set payload, oidcId, expiresAt
            { upsert: true }
        );
    }

    /**
     * Finds an OIDC artifact by its provider ID ('oidcId').
     * Returns undefined if expired or already consumed.
     */
    async find(id: string): Promise<AdapterPayload | undefined> {
        const result = await this.collection.findOne({ oidcId: id });
        if (!result) return undefined;

        // Check expiration
        if (result.expiresAt && result.expiresAt < new Date()) {
            await this.destroy(id);
            return undefined;
        }

        // *** ADDED CHECK: Return undefined if already consumed ***
        if (result.consumed) {
            logger.info(`[MongoAdapter:${this.name}] Find - Already Consumed: ${id}`);
            // Optionally delete consumed codes after a short grace period? For now, just don't return it.
            // await this.destroy(id);
            return undefined;
        }

        const { _id, oidcId, ...payload } = result;
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
             logger.info(`[MongoAdapter:${this.name}] FindByUid - Already Consumed: ${uid}`);
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
             logger.info(`[MongoAdapter:${this.name}] FindByUserCode - Already Consumed: ${userCode}`);
             return undefined;
         }
         const { _id, oidcId, ...payload } = result;
         return payload as AdapterPayload;
    }

    /**
     * Destroys an OIDC artifact by its provider ID ('oidcId').
     */
    async destroy(id: string): Promise<void> {
        // Delete using the dedicated 'oidcId' field.
        await this.collection.deleteOne({ oidcId: id });
    }

    /**
     * Revokes OIDC artifacts associated with a specific grantId.
     */
    async revokeByGrantId(grantId: string): Promise<void> {
        // This logic remains the same - delete based on the 'grantId' field.
        const modelsToRevoke = ['AccessToken', 'AuthorizationCode', 'RefreshToken', 'DeviceCode', 'BackchannelAuthenticationRequest'];
        logger.info(`[MongoAdapter] Revoking by Grant ID: ${grantId}`);
        for (const modelName of modelsToRevoke) {
             try {
                 // Need to get collection using lowercase name convention
                 const coll = getCollection(`${modelName.toLowerCase()}s`);
                 const result = await coll.deleteMany({ grantId });
                 if (result.deletedCount > 0) {
                     logger.info(`[MongoAdapter:${modelName}] Revoked ${result.deletedCount} items for Grant ID: ${grantId}`);
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
        // Update using the dedicated 'oidcId' field.
        const result = await this.collection.updateOne(
            { oidcId: id },
            // Ensure the consumed field exists and is only set once
            // { $currentDate: { consumed: { $type: 'timestamp' } } }
            { $set: { consumed: Math.floor(Date.now() / 1000) } }
        );
         // if (result.modifiedCount === 1) { logger.info(`[MongoAdapter:${this.name}] Consumed ID: ${id}`); }
    }
}

export default function adapterFactory(name: string): Adapter {
    return new MongoDbAdapter(name);
}