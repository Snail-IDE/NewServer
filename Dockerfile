# Use a Node.js base image
FROM node:14

# Set the working directory
WORKDIR /app

# Copy package files to install dependencies
COPY package*.json ./

# Install Node.js dependencies
RUN npm install

# Copy the entire application code
COPY . .

# Specify the command to start the Node.js application
CMD ["node", "index.js"]
