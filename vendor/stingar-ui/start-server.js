#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

// Version resolution priority (see Roadmap/plans/VERSIONING_OVERHAUL_PLAN.md):
//   1. STINGAR_VERSION env var (baked into the image by Dockerfile)
//   2. package.json "version" field, re-prefixed with "v" to match
//      the canonical STINGAR format
//   3. literal "unknown" -- never silently fall back to a stale literal
function resolveVersion() {
    const fromEnv = process.env.STINGAR_VERSION;
    if (fromEnv && fromEnv.trim()) {
        return fromEnv.trim();
    }
    try {
        const packageJsonPath = path.join(__dirname, 'package.json');
        const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
        if (pkg && typeof pkg.version === 'string' && pkg.version.trim()) {
            const raw = pkg.version.trim();
            return raw.startsWith('v') ? raw : 'v' + raw;
        }
    } catch (_err) {
        // fall through
    }
    console.warn('[stingar-ui] STINGAR_VERSION unset and package.json unreadable; reporting "unknown"');
    return 'unknown';
}

const version = resolveVersion();

// Print the STINGAR banner
console.log(`
███████╗████████╗██╗███╗   ██╗ ██████╗  █████╗ ██████╗ 
██╔════╝╚══██╔══╝██║████╗  ██║██╔════╝ ██╔══██╗██╔══██╗
███████╗   ██║   ██║██╔██╗ ██║██║  ███╗███████║██████╔╝
╚════██║   ██║   ██║██║╚██╗██║██║   ██║██╔══██║██╔══██╗
███████║   ██║   ██║██║ ╚████║╚██████╔╝██║  ██║██║  ██║
╚══════╝   ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
Threat Intelligence Platform for Higher Ed and Research
Version: ${version}
Copyright (C) 2021-2026 Forewarned, Inc.
───────────────────────────────────────────────────────
`);

// Check if server.js exists (standalone mode) or use next start
const serverJsPath = path.join(__dirname, 'server.js');
if (fs.existsSync(serverJsPath)) {
    // Standalone mode: require the server.js file
    require('./server.js');
} else {
    // Regular mode: spawn next start
    const nextStart = spawn('npx', ['next', 'start'], {
        stdio: 'inherit',
        shell: true
    });

    nextStart.on('error', (error) => {
        console.error('Failed to start Next.js server:', error);
        process.exit(1);
    });

    process.on('SIGTERM', () => {
        nextStart.kill('SIGTERM');
    });

    process.on('SIGINT', () => {
        nextStart.kill('SIGINT');
    });
}

