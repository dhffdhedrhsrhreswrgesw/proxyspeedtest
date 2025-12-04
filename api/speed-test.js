// /api/speed-test.js
// Optional: set IPINFO_TOKEN in Vercel to enable ASN/ORG checks (ipinfo.io)

const HOSTING_PROVIDERS = [
  'amazon', 'aws', 'digitalocean', 'linode', 'google', 'google cloud',
  'microsoft', 'azure', 'hetzner', 'ovh', 'cloudflare', 'vultr', 'dreamhost'
];

const PRIVATE_RE = /^(::ffff:)?(?:10\.|172\.(1[6-9]|2\d|3[0-1])\.|192\.168\.)/;
const PROXY_HEADERS = ['x-forwarded-for','x-forwarded-host','via','x-real-ip','forwarded','x-forwarded-proto'];

export default async function handler(req, res) {
  // Minimal CORS
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  try {
    const start = process.hrtime.bigint();

    // normalize IP (prefer XFF)
    const rawXff = req.headers['x-forwarded-for'];
    const xff = rawXff ? String(rawXff).split(',')[0].trim() : null;
    let ip = xff || req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
    ip = ip.replace(/^::ffff:/, ''); // handle IPv4-mapped IPv6

    const rtMs = Number((process.hrtime.bigint() - start) / 1000000n);

    // rating map (compact)
    const rating = (() => {
      if (rtMs < 50) return { level:'SUPER FAST', score:100, emoji:'⚡', rec:'Perfect for realtime' };
      if (rtMs < 100) return { level:'VERY FAST', score:90, emoji:'🚀', rec:'Excellent for streaming' };
      if (rtMs < 200) return { level:'FAST', score:75, emoji:'✨', rec:'Good for browsing' };
      if (rtMs < 400) return { level:'NORMAL', score:60, emoji:'👍', rec:'Average' };
      if (rtMs < 800) return { level:'SLOW', score:40, emoji:'🐌', rec:'Check network/proxy' };
      return { level:'VERY SLOW', score:20, emoji:'🐢', rec:'Optimize network' };
    })();

    // header heuristics
    const headerFlags = PROXY_HEADERS.filter(h => req.headers[h] !== undefined);
    const multipleIps = rawXff && rawXff.includes(',');
    const xffHasPrivate = rawXff && rawXff.split(',').some(p => PRIVATE_RE.test(p.trim()));
    const ua = String(req.headers['user-agent'] || '').toLowerCase();

    // basic proxy/vpn reasons
    const reasons = [
      ...(headerFlags.length ? [`proxy-headers:${headerFlags.join(',')}`] : []),
      ...(multipleIps ? ['xff-multiple'] : []),
      ...(xffHasPrivate ? ['xff-private'] : []),
      ...(PRIVATE_RE.test(ip) ? ['client-private-ip'] : []),
      ...(ua && (/curl|wget|python-requests|httpclient|postman|libhttp/.test(ua)) ? ['scripted-ua'] : [])
    ];

    // optional IP intelligence via ipinfo.io (if configured)
    let ipinfo = null, hostFlag = null;
    const token = process.env.IPINFO_TOKEN;
    if (token && ip && ip !== 'unknown') {
      try {
        const r = await fetch(`https://ipinfo.io/${ip}/json?token=${token}`);
        if (r.ok) {
          ipinfo = await r.json();
          const org = (ipinfo.org || '').toLowerCase();
          if (HOSTING_PROVIDERS.some(p => org.includes(p))) {
            hostFlag = `hosting:${org}`;
            reasons.push(hostFlag);
          }
        }
      } catch (e) {
        // ignore external lookup failures (still return heuristics)
      }
    }

    const isProxyDetected = reasons.length > 0;

    res.status(200).json({
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
        ip, userAgent: req.headers['user-agent'] || 'unknown', host: req.headers.host || 'unknown',
        forwardedFor: rawXff || null
      },
      proxyCheck: {
        isProxyDetected,
        reasons,                   // short list of why we flagged it
        ipinfo: ipinfo ? { ip: ipinfo.ip, org: ipinfo.org, country: ipinfo.country } : null,
        note: token ? 'ipinfo.org used for ASN/org check' : 'Set IPINFO_TOKEN to enable ASN/org verification'
      }
    });

  } catch (error) {
    res.status(500).json({ success:false, error: String(error) });
  }
}
