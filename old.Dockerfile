# ---- Stage 1: Builder ----
    FROM node:22-alpine AS builder
    WORKDIR /app
    
    # Copy package definition AND lock file
    # Ensure package-lock.json (for npm) or yarn.lock (for yarn) exists locally
    COPY package.json package-lock.json* ./
    # --- OR for Yarn ---
    # COPY package.json yarn.lock ./
    
    # Install *all* dependencies using the lock file
    # Use npm ci for npm projects (requires package-lock.json)
    RUN npm ci
    # --- OR for Yarn ---
    # RUN yarn install --frozen-lockfile
    
    # Copy the rest of the application source code
    COPY . .
    
    # Compile TypeScript to JavaScript using npx
    RUN npx tsc
    # The 'dist' folder now contains the compiled JS
    
    # ---- Stage 2: Runner ----
    FROM node:22-alpine
    ENV NODE_ENV=production
    ENV PORT=5001
    ENV ISSUER_URL=https://auth.arademia.com
    WORKDIR /app
    
    # Copy package definition AND lock file again for production install
    COPY package.json package-lock.json* ./
    # --- OR for Yarn ---
    # COPY package.json yarn.lock ./
    
    # Install ONLY production dependencies using the lock file
    # Use npm ci for npm projects
    RUN npm ci --omit=dev
    # --- OR for Yarn ---
    # RUN yarn install --frozen-lockfile --production
    
    RUN npm rebuild bcrypt --build-from-source
    
    # Copy the compiled JavaScript code from the builder stage
    COPY --from=builder /app/dist ./dist
    
    # Copy views from the src directory in the build context
    # to the dist/views directory inside the container's app directory
    # to match app.set('views', path.join(__dirname, './views')) in server.ts
    COPY src/views ./dist/views
    
    EXPOSE 5001
    CMD ["node", "dist/server.js"]