// /api/speed-test.js
// Optional env:
//   PROXYCHECK_KEY - your proxycheck.io key (optional)
//   IPINFO_TOKEN   - your ipinfo.io token (optional)

const HOSTING_PROVIDERS = [
  'amazon', 'aws', 'digitalocean', 'linode', 'google', 'google cloud',
  'microsoft', 'azure', 'hetzner', 'ovh', 'cloudflare', 'vultr', 'dreamhost'
];

const PRIVATE_RE = /^(::ffff:)?(?:10\.|172\.(1[6-9]|2\d|3[0-1])\.|192\.168\.|127\.|::1\b)/i;
const PROXY_HEADERS = ['x-forwarded-for','x-forwarded-host','via','x-real-ip','forwarded','x-forwarded-proto'];

// Simple in-memory cache for external lookups (ip -> {value, expiresAt})
const lookupCache = new Map();
function cacheSet(key, value, ttlMs = 60_000) {
  lookupCache.set(key, { value, expiresAt: Date.now() + ttlMs });
}
function cacheGet(key) {
  const e = lookupCache.get(key);
  if (!e) return null;
  if (Date.now() > e.expiresAt) { lookupCache.delete(key); return null; }
  return e.value;
}

export default async function handler(req, res) {
  // Minimal CORS for client usage
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  try {
    const start = process.hrtime.bigint();

    // Normalize client IP (prefer first XFF)
    const rawXff = String(req.headers['x-forwarded-for'] || '');
    const xffFirst = rawXff ? rawXff.split(',')[0].trim() : null;
    let ip = xffFirst || req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
    ip = String(ip).replace(/^::ffff:/, '');

    const rtMs = Number((process.hrtime.bigint() - start) / 1_000_000n);

    // Basic rating (server execution time — not real RTT)
    const rating = (() => {
      if (rtMs < 50) return { level: 'SUPER FAST', score: 100, emoji: '⚡', rec: 'Perfect for realtime' };
      if (rtMs < 100) return { level: 'VERY FAST', score: 90, emoji: '🚀', rec: 'Great for streaming' };
      if (rtMs < 200) return { level: 'FAST', score: 75, emoji: '✨', rec: 'Good for browsing' };
      if (rtMs < 400) return { level: 'NORMAL', score: 60, emoji: '👍', rec: 'Average' };
      if (rtMs < 800) return { level: 'SLOW', score: 40, emoji: '🐌', rec: 'Check network/proxy' };
      return { level: 'VERY SLOW', score: 20, emoji: '🐢', rec: 'Optimize network' };
    })();

    const detection = await detectProxyOrVpn({
      ip,
      rawXff,
      headers: req.headers,
      socketRemote: (req.socket?.remoteAddress || '').replace(/^::ffff:/, '')
    });

    return res.status(200).json({
      success: true,
      timestamp: new Date().toISOString(),
      connection: {
        speed: rating.level,
        score: rating.score,
        responseTime: `${rtMs}ms`,
        emoji: rating.emoji,
        recommendation: rating.rec
      },
      client: {
        ip,
        userAgent: req.headers['user-agent'] || 'unknown',
        host: req.headers.host || 'unknown',
        forwardedFor: rawXff || null,
        remoteAddr: (req.socket?.remoteAddress || null)
      },
      proxyCheck: detection
    });
  } catch (err) {
    res.status(500).json({ success: false, error: String(err) });
  }
}

// ----- detection logic -----
// returns { isProxy, isVPN, reasons: [], ipinfo: { org, country } | null }
async function detectProxyOrVpn({ ip, rawXff, headers, socketRemote }) {
  const reasons = [];

  // 1) quick sanity
  if (!ip || ip === 'unknown') {
    reasons.push('no-ip');
    return { isProxy: false, isVPN: false, reasons, ipinfo: null };
  }

  // 2) header heuristics (but Vercel sets XFF for normal users — so be conservative)
  const xff = rawXff || '';
  const xffParts = xff ? xff.split(',').map(s => s.trim()).filter(Boolean) : [];

  // multiple addresses in XFF -> likely proxy chain / NAT / lb
  if (xffParts.length > 1) {
    reasons.push('xff-multiple');
  }

  // private -> public hop: if first XFF is private but final is public, suspicious
  if (xffParts.length >= 1) {
    const first = xffParts[0].replace(/^::ffff:/, '');
    const last = xffParts[xffParts.length - 1].replace(/^::ffff:/, '');
    if (isPrivate(first) && !isPrivate(last)) reasons.push('xff-private-to-public');
  }

  // if socket remote (the immediate peer the function sees) is a known private addr and xff shows a different public ip => normal (device behind NAT)
  if (isPrivate(socketRemote) && xffParts.length === 1 && !isPrivate(xffParts[0])) {
    // typical NAT => NOT a sign of proxy by itself
  }

  // suspicious UA (scripted clients)
  const ua = String(headers['user-agent'] || '').toLowerCase();
  if (ua && /curl|wget|python-requests|httpclient|postman|libhttp|okhttp|node-fetch/.test(ua)) {
    reasons.push('scripted-ua');
  }

  // presence of proxy headers alone is NOT enough on Vercel (skip), but record them for info
  const presentProxyHeaders = PROXY_HEADERS.filter(h => headers[h]);
  if (presentProxyHeaders.length) {
    // include as informational reason but do not count as a definitive proxy indicator
    reasons.push(`proxy-headers:${presentProxyHeaders.join(',')}`);
  }

  // 3) external enrichment (optional): ProxyCheck and/or ipinfo
  let ipinfo = null;
  let externalFlag = null;

  // Prefer proxycheck when configured (it also returns whether VPN/proxy)
  const proxycheckKey = process.env.PROXYCHECK_KEY;
  if (proxycheckKey || true) { // allow anonymous calls if you want; keep try/catch
    try {
      const cacheKey = `proxycheck:${ip}`;
      const cached = cacheGet(cacheKey);
      if (cached) {
        if (cached.isProxy) reasons.push(...cached.reasons || []);
        externalFlag = cached.flag || null;
      } else {
        const url = proxycheckKey
          ? `https://proxycheck.io/v2/${ip}?key=${proxycheckKey}&vpn=1&asn=1`
          : `https://proxycheck.io/v2/${ip}?vpn=1&asn=1`;
        const r = await fetch(url, { headers: { 'User-Agent': 'vercel-speed-test' } });
        if (r.ok) {
          const j = await r.json();
          const info = j[ip] || {};
          const isProxy = info.proxy === 'yes';
          const type = (info.type || '').toUpperCase();
          if (isProxy) {
            reasons.push(`proxycheck:${type || 'proxy'}`);
            externalFlag = `proxycheck:${type || 'proxy'}`;
          }
          cacheSet(cacheKey, { isProxy, reasons: isProxy ? [`proxycheck:${type||'proxy'}`] : [], flag: externalFlag }, 60_000);
        }
      }
    } catch (e) {
      // ignore external failures
    }
  }

  // ipinfo to detect hosting providers / ASN (optional but useful)
  const ipinfoToken = process.env.IPINFO_TOKEN;
  if (ipinfoToken) {
    try {
      const cacheKey = `ipinfo:${ip}`;
      const cached = cacheGet(cacheKey);
      if (cached) {
        ipinfo = cached;
      } else {
        const r = await fetch(`https://ipinfo.io/${ip}/json?token=${ipinfoToken}`);
        if (r.ok) {
          ipinfo = await r.json();
          cacheSet(cacheKey, ipinfo, 60_000);
        }
      }
      if (ipinfo?.org) {
        const org = String(ipinfo.org).toLowerCase();
        if (HOSTING_PROVIDERS.some(p => org.includes(p))) {
          reasons.push(`hosting-provider:${ipinfo.org}`);
        }
      }
    } catch (e) { /* ignore */ }
  }

  // decide final booleans
  // Consider proxy detected if:
  // - proxycheck flagged it OR
  // - multiple XFF entries OR
  // - private->public XFF hop OR
  // - hosting provider org (ipinfo)
  const isProxy = reasons.some(r => r.startsWith('proxycheck:') || r === 'xff-multiple' || r === 'xff-private-to-public' || r.startsWith('hosting-provider:'));
  // isVPN true if proxycheck returned VPN specifically OR proxy type indicated VPN
  const isVPN = reasons.some(r => r.startsWith('proxycheck:') && r.toLowerCase().includes('vpn'));

  return {
    isProxy,
    isVPN,
    reasons,
    ipinfo: ipinfo ? { ip: ipinfo.ip || ip, org: ipinfo.org || null, country: ipinfo.country || null } : null,
    note: ipinfoToken ? 'ipinfo used' : 'set IPINFO_TOKEN to check ASN/org',
  };
}

function isPrivate(addr) {
  if (!addr) return false;
  return PRIVATE_RE.test(String(addr));
}
