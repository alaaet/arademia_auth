import mongoose, { Schema, Document } from 'mongoose';
import bcrypt from 'bcrypt';
import logger from '../config/middlewares/logger';

// Define allowed user roles
export type UserRole = 'student' | 'teacher' | 'admin';

// Update the interface to include new fields
export interface IUser extends Document {
  moodleId?: number; // Link to Moodle user ID (optional)
  username: string;
  password?: string; // Make required during registration logic, store hash
  email: string;
  firstName?: string; // Changed from fullname
  lastName: string;  // Changed from fullname, make required
  role: UserRole; // Added: Role of the user
  isValidated: boolean; // Added: Primarily for teacher validation by admin
  isProfileComplete: boolean; // Added: Tracks if extended profile (on arademia_api) is filled
  createdAt: Date;
  updatedAt: Date;
}

const UserSchema: Schema = new Schema({
  moodleId: { type: Number, unique: true, sparse: true },
  username: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
  password: { type: String, required: true }, // Password is required for registration
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
  firstName: { type: String, trim: true },
  lastName: { type: String, required: true, trim: true },
  // Add new fields to the schema
  role: {
      type: String,
      enum: ['student', 'teacher', 'admin'], // Define allowed roles
      required: true
  },
  isValidated: { // False by default, especially for teachers needing admin approval
      type: Boolean,
      default: false
  },
  isProfileComplete: { // User needs to fill profile details later
      type: Boolean,
      default: false
  },
}, { timestamps: true });

// Pre-save hook for password hashing (ensure this is present and correct)
UserSchema.pre<IUser>('save', async function (next) {
    if (!this.isModified('password') || !this.password) {
        return next();
    }
    try {
        const saltRounds = 10;
        const salt = await bcrypt.genSalt(saltRounds);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error: any) {
        logger.error(`Error hashing password for user ${this.username}:`, error);
        next(error);
    }
});

export default mongoose.model<IUser>('User', UserSchema);