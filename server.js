const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const fetch = require('node-fetch');
const { URL } = require('url');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3001;

// Environment configuration
const CONFIG = {
    NODE_ENV: process.env.NODE_ENV || 'development',
    MAX_CACHE_SIZE: parseInt(process.env.MAX_CACHE_SIZE) || 500,
    CACHE_TTL: parseInt(process.env.CACHE_TTL) || 300000, // 5 minutes
    PLAYLIST_CACHE_TTL: parseInt(process.env.PLAYLIST_CACHE_TTL) || 30000, // 30 seconds
    MAX_RETRIES: parseInt(process.env.MAX_RETRIES) || 3,
    TIMEOUT: parseInt(process.env.TIMEOUT) || 30000,
    RATE_LIMIT_WINDOW: parseInt(process.env.RATE_LIMIT_WINDOW) || 900000, // 15 minutes
    RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX) || 2000,
    STRICT_RATE_LIMIT_MAX: parseInt(process.env.STRICT_RATE_LIMIT_MAX) || 500,
    ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['*'],
    BLOCKED_DOMAINS: process.env.BLOCKED_DOMAINS ? process.env.BLOCKED_DOMAINS.split(',') : ['localhost', '127.0.0.1', '0.0.0.0', '::1'],
    ALLOWED_DOMAINS: process.env.ALLOWED_DOMAINS ? process.env.ALLOWED_DOMAINS.split(',') : null,
    MAX_CONCURRENT_REQUESTS: parseInt(process.env.MAX_CONCURRENT_REQUESTS) || 100
};

// Simple in-memory cache implementation (no external dependencies)
class SimpleCache {
    constructor(maxSize = 500, ttl = 300000) {
        this.cache = new Map();
        this.maxSize = maxSize;
        this.ttl = ttl;
    }

    set(key, value, customTtl = null) {
        const expiry = Date.now() + (customTtl || this.ttl);

        // Remove oldest entries if cache is full
        if (this.cache.size >= this.maxSize) {
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }

        this.cache.set(key, { value, expiry, timestamp: Date.now() });
    }

    get(key) {
        const item = this.cache.get(key);
        if (!item) return null;

        if (Date.now() > item.expiry) {
            this.cache.delete(key);
            return null;
        }

        return item.value;
    }

    has(key) {
        const item = this.cache.get(key);
        if (!item) return false;

        if (Date.now() > item.expiry) {
            this.cache.delete(key);
            return false;
        }

        return true;
    }

    delete(key) {
        return this.cache.delete(key);
    }

    clear() {
        this.cache.clear();
    }

    size() {
        // Clean up expired items first
        const now = Date.now();
        for (const [key, item] of this.cache.entries()) {
            if (now > item.expiry) {
                this.cache.delete(key);
            }
        }
        return this.cache.size;
    }

    keys() {
        return Array.from(this.cache.keys());
    }

    // Get cache statistics
    getStats() {
        const now = Date.now();
        let expired = 0;
        let totalSize = 0;

        for (const [key, item] of this.cache.entries()) {
            if (now > item.expiry) {
                expired++;
            }

            if (item.value && typeof item.value === 'object' && item.value.content) {
                totalSize += Buffer.isBuffer(item.value.content) ?
                    item.value.content.length :
                    item.value.content.length * 2; // Rough string size estimate
            }
        }

        return {
            size: this.cache.size,
            maxSize: this.maxSize,
            expired,
            totalSize,
            ttl: this.ttl
        };
    }
}

// Security middleware
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: false
}));

// Compression middleware
app.use(compression({
    filter: (req, res) => {
        if (req.headers['x-no-compression']) return false;
        return compression.filter(req, res);
    },
    level: 6,
    threshold: 1024
}));

// Trust proxy for rate limiting behind load balancers
app.set('trust proxy', 1);

// Enhanced rate limiting with different tiers
const createRateLimiter = (windowMs, max, skipSuccessfulRequests = false) => {
    return rateLimit({
        windowMs,
        max,
        skipSuccessfulRequests,
        standardHeaders: true,
        legacyHeaders: false,
        message: { error: 'Rate limit exceeded. Please try again later.' },
        keyGenerator: (req) => {
            return req.ip + ':' + (req.get('User-Agent') || '').slice(0, 50);
        }
    });
};

const generalLimiter = createRateLimiter(CONFIG.RATE_LIMIT_WINDOW, CONFIG.RATE_LIMIT_MAX, true);
const proxyLimiter = createRateLimiter(60000, CONFIG.STRICT_RATE_LIMIT_MAX); // 1 minute window
const healthLimiter = createRateLimiter(60000, 60); // 60 requests per minute for health

// Advanced CORS configuration
const corsOptions = {
    origin: (origin, callback) => {
        if (!origin || CONFIG.ALLOWED_ORIGINS.includes('*')) {
            return callback(null, true);
        }

        const isAllowed = CONFIG.ALLOWED_ORIGINS.some(allowedOrigin => {
            if (allowedOrigin.includes('*')) {
                const regex = new RegExp(allowedOrigin.replace(/\*/g, '.*'));
                return regex.test(origin);
            }
            return origin === allowedOrigin;
        });

        callback(null, isAllowed);
    },
    methods: ['GET', 'POST', 'OPTIONS', 'HEAD'],
    allowedHeaders: [
        'Content-Type',
        'Authorization',
        'Range',
        'User-Agent',
        'Referer',
        'Origin',
        'X-Requested-With',
        'X-Forwarded-For',
        'X-Real-IP'
    ],
    exposedHeaders: [
        'Content-Length',
        'Content-Range',
        'Accept-Ranges',
        'Content-Type',
        'Cache-Control',
        'X-Proxy-Cache'
    ],
    credentials: false,
    maxAge: 86400,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// Request parsing with limits
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Initialize caches
const playlistCache = new SimpleCache(CONFIG.MAX_CACHE_SIZE, CONFIG.PLAYLIST_CACHE_TTL);
const segmentCache = new SimpleCache(CONFIG.MAX_CACHE_SIZE * 2, CONFIG.CACHE_TTL);

// Request tracking for concurrent limit
let activeRequests = 0;
const requestQueue = [];

// Concurrency control middleware
const concurrencyControl = (req, res, next) => {
    if (activeRequests >= CONFIG.MAX_CONCURRENT_REQUESTS) {
        return res.status(503).json({
            error: 'Server busy. Too many concurrent requests.',
            retryAfter: 1
        });
    }

    activeRequests++;
    res.on('finish', () => {
        activeRequests--;
    });
    res.on('close', () => {
        activeRequests--;
    });

    next();
};

// Enhanced URL validation with domain whitelisting
function validateUrl(urlString) {
    try {
        const url = new URL(urlString);

        // Protocol check
        if (!['http:', 'https:'].includes(url.protocol)) {
            return { valid: false, error: 'Only HTTP/HTTPS protocols allowed' };
        }

        // Blocked domains check
        if (CONFIG.BLOCKED_DOMAINS.includes(url.hostname)) {
            return { valid: false, error: 'Domain is blocked' };
        }

        // Domain whitelist check
        if (CONFIG.ALLOWED_DOMAINS && CONFIG.ALLOWED_DOMAINS.length > 0) {
            const isAllowed = CONFIG.ALLOWED_DOMAINS.some(domain => {
                if (domain.startsWith('*.')) {
                    return url.hostname.endsWith(domain.slice(2));
                }
                return url.hostname === domain || url.hostname.endsWith('.' + domain);
            });

            if (!isAllowed) {
                return { valid: false, error: 'Domain not in whitelist' };
            }
        }

        // Private IP check
        const hostname = url.hostname;
        if (hostname.match(/^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|169\.254\.|fe80:|::1|localhost)/) ||
            hostname === '127.0.0.1' || hostname === '0.0.0.0') {
            return { valid: false, error: 'Private/local addresses not allowed' };
        }

        return { valid: true, url };
    } catch (error) {
        return { valid: false, error: 'Invalid URL format' };
    }
}

// Enhanced user agent rotation with real browser signatures
const USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0'
];

// Smart header generation
function generateRequestHeaders(originalHeaders = {}, url = '') {
    const userAgent = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
    const urlObj = new URL(url);

    const headers = {
        'User-Agent': userAgent,
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'cross-site',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'DNT': '1'
    };

    // Set appropriate Accept header based on file type
    if (url.includes('.m3u8') || url.includes('.m3u')) {
        headers['Accept'] = 'application/vnd.apple.mpegurl, application/x-mpegURL, text/plain, */*';
    } else if (url.includes('.ts') || url.includes('.mp4') || url.includes('.m4s')) {
        headers['Accept'] = 'video/*, */*';
    }

    // Add referer from same domain
    headers['Referer'] = `${urlObj.protocol}//${urlObj.hostname}/`;

    // Forward important headers from original request
    if (originalHeaders.range) headers['Range'] = originalHeaders.range;
    if (originalHeaders['if-range']) headers['If-Range'] = originalHeaders['if-range'];
    if (originalHeaders['if-none-match']) headers['If-None-Match'] = originalHeaders['if-none-match'];
    if (originalHeaders['if-modified-since']) headers['If-Modified-Since'] = originalHeaders['if-modified-since'];

    return headers;
}

// Advanced retry mechanism with circuit breaker pattern
const failedHosts = new Map();

async function fetchWithRetry(url, options, maxRetries = CONFIG.MAX_RETRIES) {
    const hostname = new URL(url).hostname;

    // Circuit breaker: skip if host has been failing recently
    const hostFailures = failedHosts.get(hostname);
    if (hostFailures && hostFailures.count > 5 && Date.now() - hostFailures.lastFail < 300000) {
        throw new Error(`Circuit breaker: ${hostname} temporarily blocked due to repeated failures`);
    }

    for (let attempt = 0; attempt < maxRetries; attempt++) {
        try {
            const timeoutMs = CONFIG.TIMEOUT + (attempt * 5000);

            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

            const response = await fetch(url, {
                ...options,
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (response.ok) {
                // Reset failure count on success
                failedHosts.delete(hostname);
                return response;
            }

            // Don't retry on client errors (except 429)
            if (response.status >= 400 && response.status < 500 && response.status !== 429) {
                return response;
            }

            if (attempt === maxRetries - 1) {
                // Track failed hosts
                const currentFailures = failedHosts.get(hostname) || { count: 0, lastFail: 0 };
                failedHosts.set(hostname, {
                    count: currentFailures.count + 1,
                    lastFail: Date.now()
                });
                return response;
            }

            // Exponential backoff with jitter
            const delay = Math.min(1000 * Math.pow(2, attempt) + Math.random() * 1000, 10000);
            await new Promise(resolve => setTimeout(resolve, delay));

        } catch (error) {
            if (error.name === 'AbortError') {
                error.code = 'ETIMEDOUT';
            }

            if (attempt === maxRetries - 1) {
                // Track failed hosts
                const currentFailures = failedHosts.get(hostname) || { count: 0, lastFail: 0 };
                failedHosts.set(hostname, {
                    count: currentFailures.count + 1,
                    lastFail: Date.now()
                });
                throw error;
            }

            // Exponential backoff with jitter
            const delay = Math.min(1000 * Math.pow(2, attempt) + Math.random() * 1000, 10000);
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }
}

// Enhanced health check with system metrics
app.get('/health', healthLimiter, (req, res) => {
    const memUsage = process.memoryUsage();
    const uptime = process.uptime();

    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: Math.round(uptime),
        version: '3.0.0',
        environment: CONFIG.NODE_ENV,
        memory: {
            used: Math.round(memUsage.heapUsed / 1024 / 1024),
            total: Math.round(memUsage.heapTotal / 1024 / 1024),
            external: Math.round(memUsage.external / 1024 / 1024)
        },
        cache: {
            playlists: {
                size: playlistCache.size(),
                ...playlistCache.getStats()
            },
            segments: {
                size: segmentCache.size(),
                ...segmentCache.getStats()
            }
        },
        system: {
            activeRequests,
            failedHosts: failedHosts.size,
            nodeVersion: process.version,
            platform: process.platform
        },
        limits: {
            maxConcurrentRequests: CONFIG.MAX_CONCURRENT_REQUESTS,
            rateLimit: CONFIG.RATE_LIMIT_MAX,
            cacheSize: CONFIG.MAX_CACHE_SIZE
        }
    });
});

// Main HLS/Media proxy endpoint with NextJS optimization
app.get('/api/proxy', concurrencyControl, proxyLimiter, async (req, res) => {
    const startTime = Date.now();

    try {
        const { url, force_refresh, format } = req.query;

        if (!url) {
            return res.status(400).json({
                error: 'Missing required parameter: url',
                example: '/api/proxy?url=https://example.com/playlist.m3u8'
            });
        }

        // URL validation
        const validation = validateUrl(decodeURIComponent(url));
        if (!validation.valid) {
            return res.status(400).json({
                error: validation.error,
                url: url.substring(0, 100) + (url.length > 100 ? '...' : '')
            });
        }

        const targetUrl = validation.url.href;
        const cacheKey = crypto.createHash('sha256').update(targetUrl).digest('hex').substring(0, 16);

        // Determine content type
        const isPlaylist = targetUrl.includes('.m3u8') ||
            targetUrl.includes('.m3u') ||
            format === 'playlist';

        const isSegment = targetUrl.includes('.ts') ||
            targetUrl.includes('.m4s') ||
            targetUrl.includes('.mp4') ||
            format === 'segment';

        // Cache check (skip for force refresh)
        if (!force_refresh) {
            const cache = isPlaylist ? playlistCache : segmentCache;
            const cached = cache.get(cacheKey);

            if (cached) {
                console.log(`Cache hit for: ${targetUrl.substring(0, 80)}...`);

                // Set cache headers
                res.set({
                    ...cached.headers,
                    'X-Proxy-Cache': 'HIT',
                    'X-Proxy-Time': '0ms'
                });

                return cached.isBuffer ? res.send(cached.content) : res.send(cached.content);
            }
        }

        console.log(`Proxying ${isPlaylist ? 'playlist' : 'media'}: ${targetUrl.substring(0, 80)}...`);

        // Fetch with retry
        const response = await fetchWithRetry(targetUrl, {
            method: 'GET',
            headers: generateRequestHeaders(req.headers, targetUrl)
        });

        if (!response.ok) {
            console.error(`Upstream error ${response.status} for: ${targetUrl}`);
            return res.status(response.status).json({
                error: `Upstream server returned ${response.status}: ${response.statusText}`,
                url: targetUrl.substring(0, 100)
            });
        }

        // Response headers
        const contentType = response.headers.get('content-type') ||
            (isPlaylist ? 'application/vnd.apple.mpegurl' : 'application/octet-stream');

        const responseHeaders = {
            'Content-Type': contentType,
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Range, Content-Type, Authorization',
            'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Accept-Ranges, X-Proxy-Cache',
            'X-Proxy-Cache': 'MISS',
            'X-Proxy-Time': `${Date.now() - startTime}ms`,
            'Cache-Control': isPlaylist ? 'no-cache, no-store, must-revalidate' : 'public, max-age=3600',
            'Vary': 'Origin'
        };

        // Forward range and content headers
        ['content-length', 'content-range', 'accept-ranges', 'etag', 'last-modified'].forEach(header => {
            if (response.headers.get(header)) {
                responseHeaders[header.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join('-')] =
                    response.headers.get(header);
            }
        });

        res.set(responseHeaders);
        res.status(response.status);

        if (isPlaylist) {
            // Process playlist files
            const text = await response.text();
            const baseUrl = targetUrl.substring(0, targetUrl.lastIndexOf('/') + 1);

            const modifiedContent = text.split('\n').map(line => {
                if (line.startsWith('#') || line.trim() === '') {
                    return line;
                }

                if (line.trim().length > 0) {
                    let segmentUrl = line.trim();

                    // Convert relative URLs to absolute
                    if (!segmentUrl.startsWith('http')) {
                        segmentUrl = baseUrl + segmentUrl;
                    }

                    // Proxy through our endpoint with format hint
                    const proxyUrl = `/api/proxy?url=${encodeURIComponent(segmentUrl)}&format=segment`;
                    return proxyUrl;
                }

                return line;
            }).join('\n');

            // Cache processed playlist
            playlistCache.set(cacheKey, {
                content: modifiedContent,
                headers: responseHeaders,
                isBuffer: false,
                timestamp: Date.now()
            });

            res.send(modifiedContent);

        } else {
            // Handle media segments
            const buffer = await response.buffer();

            // Cache segments
            segmentCache.set(cacheKey, {
                content: buffer,
                headers: responseHeaders,
                isBuffer: true,
                timestamp: Date.now()
            });

            res.send(buffer);
        }

    } catch (error) {
        const duration = Date.now() - startTime;
        console.error(`Proxy error after ${duration}ms:`, error.message);

        // Enhanced error responses
        const errorResponses = {
            'ENOTFOUND': { status: 404, message: 'Host not found' },
            'ETIMEDOUT': { status: 408, message: 'Request timeout' },
            'ECONNREFUSED': { status: 503, message: 'Connection refused' },
            'ECONNRESET': { status: 502, message: 'Connection reset' },
            'EPROTO': { status: 502, message: 'Protocol error' },
            'CERT_EXPIRED': { status: 502, message: 'SSL certificate expired' }
        };

        const errorInfo = errorResponses[error.code] || { status: 500, message: 'Internal server error' };

        res.status(errorInfo.status).json({
            error: errorInfo.message,
            code: error.code,
            duration: `${duration}ms`,
            url: req.query.url ? req.query.url.substring(0, 100) : 'unknown',
            ...(CONFIG.NODE_ENV === 'development' && { details: error.message })
        });
    }
});

// Cache management endpoints
app.get('/api/cache/clear', generalLimiter, (req, res) => {
    const { type } = req.query;

    if (type === 'playlist') {
        playlistCache.clear();
    } else if (type === 'segment') {
        segmentCache.clear();
    } else {
        playlistCache.clear();
        segmentCache.clear();
    }

    res.json({
        message: `${type || 'All'} cache cleared successfully`,
        timestamp: new Date().toISOString()
    });
});

app.get('/api/cache/stats', generalLimiter, (req, res) => {
    res.json({
        playlists: playlistCache.getStats(),
        segments: segmentCache.getStats(),
        failedHosts: Array.from(failedHosts.entries()).map(([host, data]) => ({
            host,
            failures: data.count,
            lastFail: new Date(data.lastFail).toISOString()
        }))
    });
});

// Preflight requests with caching
app.options('*', (req, res) => {
    res.set({
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, HEAD',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, Range, User-Agent, Referer, Origin, X-Requested-With',
        'Access-Control-Max-Age': '86400',
        'Cache-Control': 'public, max-age=86400'
    });
    res.status(200).end();
});

// Request logging middleware (only in development)
if (CONFIG.NODE_ENV === 'development') {
    app.use((req, res, next) => {
        const start = Date.now();
        res.on('finish', () => {
            console.log(`${req.method} ${req.path} ${res.statusCode} ${Date.now() - start}ms`);
        });
        next();
    });
}

// Global error handler
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);

    if (res.headersSent) {
        return next(error);
    }

    res.status(500).json({
        error: 'Internal server error',
        timestamp: new Date().toISOString(),
        ...(CONFIG.NODE_ENV === 'development' && { details: error.message, stack: error.stack })
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        error: 'Endpoint not found',
        path: req.path,
        availableEndpoints: ['/health', '/api/proxy', '/api/cache/clear', '/api/cache/stats']
    });
});

// Graceful shutdown
const gracefulShutdown = (signal) => {
    console.log(`${signal} received, shutting down gracefully...`);

    // Clear caches
    playlistCache.clear();
    segmentCache.clear();
    failedHosts.clear();

    // Close server
    if (server) {
        server.close(() => {
            console.log('Server closed');
            process.exit(0);
        });
    } else {
        process.exit(0);
    }
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

const server = app.listen(PORT, () => {
    console.log(`🚀 Production HLS Proxy Server v3.0.0`);
    console.log(`📡 Port: ${PORT}`);
    console.log(`🌍 Environment: ${CONFIG.NODE_ENV}`);
    console.log(`📊 Health: http://localhost:${PORT}/health`);
    console.log(`🎥 Proxy: http://localhost:${PORT}/api/proxy?url=YOUR_URL`);
    console.log(`🗑️  Cache: http://localhost:${PORT}/api/cache/clear`);
    console.log(`⚡ Max concurrent requests: ${CONFIG.MAX_CONCURRENT_REQUESTS}`);
    console.log(`🔒 Rate limits: ${CONFIG.RATE_LIMIT_MAX}/15min, ${CONFIG.STRICT_RATE_LIMIT_MAX}/min`);

    if (CONFIG.ALLOWED_DOMAINS) {
        console.log(`🛡️  Allowed domains: ${CONFIG.ALLOWED_DOMAINS.join(', ')}`);
    }
});

server.on('error', (error) => {
    if (error.code === 'EADDRINUSE') {
        console.error(`Port ${PORT} is already in use`);
    } else {
        console.error('Server error:', error);
    }
    process.exit(1);
});

module.exports = app;