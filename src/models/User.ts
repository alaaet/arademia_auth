import mongoose, { Schema, Document } from 'mongoose';
import bcrypt from 'bcrypt'; // Import bcrypt

export interface IUser extends Document {
  moodleId?: number;
  username: string;
  password?: string; // Password is now optional initially, required for login logic
  email: string;
  fullname?: string;
  // Add other fields later
}

const UserSchema: Schema = new Schema({
  moodleId: { type: Number, unique: true, sparse: true },
  username: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String }, // Store the hashed password
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  fullname: { type: String },
}, { timestamps: true });

// --- Password Hashing Middleware ---
UserSchema.pre<IUser>('save', async function (next) {
    // Only hash the password if it has been modified (or is new) and is not empty
    if (!this.isModified('password') || !this.password) {
        return next();
    }

    try {
        console.log(`Hashing password for user: ${this.username}`);
        const saltRounds = 10; // Cost factor for hashing (adjust as needed)
        const salt = await bcrypt.genSalt(saltRounds);
        this.password = await bcrypt.hash(this.password, salt); // Hash the plain text password
        console.log(`Password hashed for user: ${this.username}`);
        next();
    } catch (error: any) {
        console.error(`Error hashing password for user ${this.username}:`, error);
        next(error); // Pass error to Mongoose/Express error handler
    }
});
// --- End Password Hashing Middleware ---

export default mongoose.model<IUser>('User', UserSchema);
