import { Request, Response, NextFunction } from 'express';
import User, { IUser, UserRole } from '../models/User'; // Adjust path if needed
import logger from '../config/middlewares/logger';

export const registerUser = async (req: Request, res: Response, next: NextFunction) => {
    const { username, email, password, firstName, lastName, role } = req.body; // Destructure new fields


    // --- Basic Input Validation ---
    if (!username || !email || !password || !role || !lastName) {
        return res.status(400).json({ message: 'Username, email, password, lastName, and role are required.' });
    }
    // Ensure role is one of the allowed types for self-registration
    if (!['student', 'teacher'].includes(role)) {
         return res.status(400).json({ message: 'Invalid role specified. Only "student" or "teacher" allowed for registration.' });
    }
    // Add more validation if needed (password complexity, email format etc.)
    // --- End Validation ---

    try {
        // --- Check for Existing User ---
        const existingUser = await User.findOne({
             $or: [
                 { username: username.toLowerCase() },
                 { email: email.toLowerCase() }
             ]
        });

        if (existingUser) {
            // Conflict error if username or email is already taken
            return res.status(409).json({ message: 'Username or email already exists.' });
        }
        // --- End Check ---

        // --- Create New User ---
        // Password will be hashed by the pre-save hook in the User model
        const newUser = new User({
            username: username.toLowerCase(),
            email: email.toLowerCase(),
            password: password, // Pass plain text password here
            firstName: firstName ? firstName : '', // Optional field
            lastName: lastName,
            role: role as UserRole,
            // Auto-validate students, teachers require admin validation later
            isValidated: role === 'student',
            // Profile starts incomplete, user needs to fill details via arademia_api
            isProfileComplete: false
        });

        await newUser.save();
        // --- End Create ---

        // --- Prepare Response ---
        // Convert to plain object and remove password hash before sending back
        const userResponse = newUser.toObject();
        delete userResponse.password;
        // delete userResponse.__v; // Optionally remove version key

        res.status(201).json({ message: 'User registered successfully', user: userResponse });
        // --- End Response ---

    } catch (error: any) {
         // Handle potential validation errors from Mongoose schema
         if (error.name === 'ValidationError') {
             const messages = Object.values(error.errors).map((el: any) => el.message);
             return res.status(400).json({ message: "Validation Failed", errors: messages });
         }
         // Log unexpected errors and pass to central error handler
         logger.error("Registration Error:", error);
         next(error);
    }
};

// Placeholder for other potential controller functions in this file
// export const checkPermissions = async (...) => { ... };