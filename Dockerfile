FROM node:18-alpine

LABEL maintainer="your-email@example.com"
LABEL description="Bulletproof HLS Proxy Server"

# Create app directory
WORKDIR /app

# Install app dependencies
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Bundle app source
COPY server.js ./

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001
USER nextjs

# Expose port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "
    const http = require('http');
    const options = { hostname: 'localhost', port: 3001, path: '/health', timeout: 2000 };
    const req = http.request(options, (res) => {
      process.exit(res.statusCode === 200 ? 0 : 1);
    });
    req.on('error', () => process.exit(1));
    req.end();
  "

# Start the server
CMD ["node", "server.js"]

// docker-compose.yml
version: '3.8'

services:
  hls-proxy:
    build: .
    ports:
      - "3001:3001"
    environment:
      - NODE_ENV=production
      - PORT=3001
      - MAX_CACHE_SIZE=1000
      - CACHE_TTL=300000
      - PLAYLIST_CACHE_TTL=30000
      - MAX_CONCURRENT_REQUESTS=200
      - RATE_LIMIT_MAX=5000
      - STRICT_RATE_LIMIT_MAX=1000
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3001/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 128M

// nginx.conf (for reverse proxy)
upstream hls_proxy {
    server 127.0.0.1:3001;
    keepalive 32;
}

server {
    listen 80;
    server_name your-proxy-domain.com;

    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-proxy-domain.com;

    # SSL Configuration
    ssl_certificate /path/to/your/cert.pem;
    ssl_certificate_key /path/to/your/private.key;
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozTLS:10m;
    ssl_session_tickets off;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;
    limit_req_zone $binary_remote_addr zone=proxy:10m rate=50r/m;

    # Proxy configuration
    location / {
        limit_req zone=api burst=20 nodelay;

        proxy_pass http://hls_proxy;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        proxy_connect_timeout 5s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }

    location /api/proxy {
        limit_req zone=proxy burst=10 nodelay;

        proxy_pass http://hls_proxy;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 10s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        proxy_buffering off;
    }

    # Health check endpoint
    location /health {
        proxy_pass http://hls_proxy;
        access_log off;
    }
}
