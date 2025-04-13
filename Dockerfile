# ---- Stage 1: Builder ----
# Use Node.js v22 on Alpine to match local environment preference
# Consider LTS (e.g., 18, 20) for production stability if 22 isn't LTS yet.
# Consider non-Alpine (e.g., node:22-slim) if native dependency issues persist.
FROM node:22-alpine AS builder

WORKDIR /app

# Copy package files
COPY package.json package-lock.json* ./

# Install *all* dependencies needed for building the application
# Using npm ci ensures a clean install based on lock file
RUN npm ci

# Copy the rest of the application source code
# Ensure .dockerignore is properly configured to exclude unnecessary files
COPY . .

# Compile TypeScript to JavaScript into the /app/dist directory
RUN npm run build
# The 'dist' folder now contains the compiled JS

# ---- Stage 2: Runner ----
# Use the same Node.js v22 base image as the builder for consistency
FROM node:22-alpine

# Set environment to production - enables optimizations in Node/Express
ENV NODE_ENV=production
# Set the port the app will run on inside the container
# This can still be overridden by runtime environment variables via docker run
ENV PORT=5001
# Default issuer URL
ENV ISSUER_URL=https://auth.arademia.com

WORKDIR /app

# Copy package.json and lock file ONLY
COPY package.json package-lock.json* ./

# Install ONLY production dependencies directly in the runner stage
# This ensures native modules like bcrypt are built for the final runtime environment
# RUN npm ci --omit=dev

# Copy the compiled JavaScript code from the builder stage
COPY --from=builder /app/dist ./dist

# Copy views if they are outside src/dist (adjust path if needed)
# Ensure this path is relative to the WORKDIR (/app)
# COPY views ./views

# Expose the port the app runs on (matches ENV PORT)
EXPOSE 5001

# Command to run the compiled application
CMD ["node", "dist/server.js"]