import mongoose from 'mongoose';
import User from '../src/models/User'; // Adjust path to your User model
import connectDB from '../src/config/database'; // Adjust path to your DB connection
import dotenv from 'dotenv';
import logger from '../src/config/middlewares/logger';

// Load environment variables (needed for database connection string)
dotenv.config({ path: '.env' }); // Ensure correct path to .env

const createUser = async () => {
  if (!process.env.MONGODB_URI) {
      logger.error("Error: MONGODB_URI not found in environment variables.");
      process.exit(1);
  }
  await connectDB(); // Connect to the database

  // // --- Define Test User ---
  const username = 'testuser';
  const given_name = 'Test';
  const family_name = 'User';
  const password = 'password123'; // Plain text password
  const email = 'testuser@example.com';
  // // --- ---
  // --- Define Test User ---
  // const username = 'ukmqd';
  // const password = 'password123'; // Plain text password
  // const email = 'admin@arademia.com';
  // const fullname = 'Alaa Abuiteiwi';
  // --- ---

  try {
    logger.debug(`Checking for existing user: ${username}`);
    let user = await User.findOne({ username: username.toLowerCase() });

    if (user) {
      logger.debug(`User ${username} already exists.`);
      // Optional: Update existing user's password if needed
      // logger.debug(`Updating password for ${username}...`);
      // user.password = password; // Set plain text, pre-save hook will hash it
      // await user.save();
      // logger.debug(`Password updated for ${username}.`);
    } else {
      // Create new user
      logger.debug(`Creating new user: ${username}`);
      user = new User ({
          username: username,
          password: password, // Provide plain text password here
          email: email,
          firstName:given_name,
          lastName: family_name,
          role: 'admin', // Set role as needed (e.g., 'admin', 'student', etc.)
          isValidated: true, // Set to true for admin or as needed
          isProfileComplete: true
      });
      await user.save(); // Pre-save hook will hash the password
      logger.debug(`User ${username} created successfully.`);
    }
  } catch (error) {
    logger.error('Error during create/update user script:', error);
  } finally {
    await mongoose.disconnect();
    logger.debug('Disconnected from DB.');
  }
};

// Execute the function
createUser();

