# Use official Node.js LTS image
FROM node:18

# Set working directory
WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install --production

# Copy the rest of the source code
COPY . .

# Expose the port your app runs on (change if not 3000)
EXPOSE 3000

# Start the service
CMD ["npm", "start"]
