# Use Python base image for heavy ML dependencies
FROM python:3.10-slim

# Install Node.js 20
RUN apt-get update && apt-get install -y curl
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
RUN apt-get install -y nodejs

# Set working directory inside the container
WORKDIR /app

# Copy dependency files first (for caching)
COPY package.json package-lock.json ./
RUN npm ci

COPY requirements-ml.txt ./
RUN pip install --no-cache-dir -r requirements-ml.txt

# Copy the rest of your Next.js and Python code
# (The .dockerignore will prevent the extension folder from being copied)
COPY . .

# Build Next.js
RUN npm run build

# Expose the port Next.js runs on
EXPOSE 3000

# Start the server
CMD ["npm", "start"]