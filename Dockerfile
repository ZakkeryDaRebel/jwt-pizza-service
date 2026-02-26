# # Use official Node.js LTS image
# FROM node:18

# # Set working directory
# WORKDIR /app

# # Copy package files and install dependencies
# COPY package*.json ./
# RUN npm install --production

# # Copy the rest of the source code
# COPY . .

# # Expose the port your app runs on (change if not 3000)
# EXPOSE 3000

# # Start the service
# CMD ["npm", "start"]

# Class Dockerfile

ARG NODE_VERSION=22

FROM node:${NODE_VERSION}-alpine
WORKDIR /user/src/app
COPY . .
RUN npm ci
EXPOSE 80
CMD ["node", "index.js", "80"]