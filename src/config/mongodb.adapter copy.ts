import { Adapter, AdapterPayload } from 'oidc-provider';
import { Collection, Db, ObjectId, Document as MongoDocument } from 'mongodb'; // Import ObjectId if needed for type checks elsewhere
import { getDb } from './database'; // Import function to get DB instance

// Helper function to get a specific collection, now generic
// Defaults to generic MongoDocument if no type is provided
const getCollection = <T extends MongoDocument = MongoDocument>(name: string): Collection<T> => {
    const db = getDb();
    if (!db) {
        throw new Error('MongoDB connection not established or DB instance not available.');
    }
    const collectionName = name.toLowerCase();
    // Return collection typed with T
    return db.collection<T>(collectionName);
};

// Define the structure stored in MongoDB, including our dedicated ID field
interface StoredPayload extends AdapterPayload {
    _id?: ObjectId; // MongoDB's native ObjectId
    oidcId: string; // The ID provided by oidc-provider
    expiresAt?: Date;
    consumed?: number; // Add consumed field if needed by consume logic
}


class MongoDbAdapter implements Adapter {
    constructor(public name: string) {
        // name is the model name passed by oidc-provider
    }

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
     */
    async find(id: string): Promise<AdapterPayload | undefined> {
        // Query using the dedicated 'oidcId' field.
        const result = await this.collection.findOne({ oidcId: id });

        if (!result) return undefined;

        // Check expiration
        if (result.expiresAt && result.expiresAt < new Date()) {
            await this.destroy(id); // Destroy using the oidcId
            return undefined;
        }

        // Return the payload, excluding MongoDB _id and our oidcId field
        const { _id, oidcId, ...payload } = result;
        return payload as AdapterPayload;
    }

    /**
     * Finds an OIDC artifact by its UID (used for sessions).
     */
    async findByUid(uid: string): Promise<AdapterPayload | undefined> {
        const result = await this.collection.findOne({ uid }); // Query by 'uid' field

         if (!result) return undefined;

         // Check expiration
         if (result.expiresAt && result.expiresAt < new Date()) {
             await this.destroy(result.oidcId); // Destroy using oidcId
             return undefined;
         }

         const { _id, oidcId, ...payload } = result;
         return payload as AdapterPayload;
    }

    /**
     * Finds an OIDC artifact by its user code (used for device flow).
     */
    async findByUserCode(userCode: string): Promise<AdapterPayload | undefined> {
         const result = await this.collection.findOne({ userCode }); // Query by 'userCode' field

         if (!result) return undefined;

         // Check expiration
          if (result.expiresAt && result.expiresAt < new Date()) {
             await this.destroy(result.oidcId); // Destroy using oidcId
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
        console.log(`[MongoAdapter] Revoking by Grant ID: ${grantId}`);
        for (const modelName of modelsToRevoke) {
             try {
                 // Need to get collection using lowercase name convention
                 const coll = getCollection(`${modelName.toLowerCase()}s`);
                 const result = await coll.deleteMany({ grantId });
                 if (result.deletedCount > 0) {
                     console.log(`[MongoAdapter:${modelName}] Revoked ${result.deletedCount} items for Grant ID: ${grantId}`);
                 }
             } catch (error) {
                  console.error(`[MongoAdapter] Error revoking ${modelName} for grantId ${grantId}:`, error);
             }
        }
    }

    /**
     * Marks an OIDC artifact (like an AuthorizationCode) as consumed using its provider ID ('oidcId').
     */
    async consume(id: string): Promise<void> {
        // Update using the dedicated 'oidcId' field.
        await this.collection.updateOne(
            { oidcId: id },
            { $set: { consumed: Math.floor(Date.now() / 1000) } } // Set consumed timestamp
        );
    }
}

// Factory function required by oidc-provider
export default function adapterFactory(name: string): Adapter {
    return new MongoDbAdapter(name);
}
