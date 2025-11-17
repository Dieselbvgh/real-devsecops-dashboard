FROM node:18-alpine

WORKDIR /app

# Install security tools
RUN apk add --no-cache docker curl

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy dashboard
COPY dashboard/ ./dashboard/

# Create necessary directories
RUN mkdir -p dashboard/data dashboard/logs dashboard/scans

# Expose port
EXPOSE 5001

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:5001/api/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

# Start the application
CMD ["npm", "start"]
