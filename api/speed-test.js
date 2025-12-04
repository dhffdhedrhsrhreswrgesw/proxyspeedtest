// api/speed-test.js
// Deploy this to Vercel in the /api folder

export default async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    const startTime = Date.now();
    
    // Get client IP
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || 
               req.headers['x-real-ip'] || 
               req.socket.remoteAddress || 
               'Unknown';
    
    // Measure response time
    const responseTime = Date.now() - startTime;
    
    // Calculate speed rating based on response time
    const rating = getSpeedRating(responseTime);
    
    // Get additional connection info
    const connectionInfo = {
      userAgent: req.headers['user-agent'] || 'Unknown',
      protocol: req.headers['x-forwarded-proto'] || 'http',
      host: req.headers['host'] || 'Unknown'
    };

    // Build response
    const response = {
      success: true,
      timestamp: new Date().toISOString(),
      connection: {
        speed: rating.level,
        score: rating.score,
        responseTime: `${responseTime}ms`,
        description: rating.description,
        emoji: rating.emoji
      },
      client: {
        ip: ip,
        userAgent: connectionInfo.userAgent,
        protocol: connectionInfo.protocol
      },
      details: {
        recommendation: rating.recommendation,
        isProxyDetected: detectProxy(req.headers)
      }
    };

    res.status(200).json(response);
    
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to test connection',
      message: error.message
    });
  }
}

function getSpeedRating(responseTime) {
  if (responseTime < 50) {
    return {
      level: 'SUPER FAST',
      score: 100,
      emoji: '⚡',
      description: 'Lightning fast connection with minimal latency',
      recommendation: 'Perfect for real-time applications and streaming'
    };
  } else if (responseTime < 100) {
    return {
      level: 'VERY FAST',
      score: 90,
      emoji: '🚀',
      description: 'Excellent connection speed',
      recommendation: 'Great for most applications and browsing'
    };
  } else if (responseTime < 200) {
    return {
      level: 'FAST',
      score: 75,
      emoji: '✨',
      description: 'Good connection with acceptable latency',
      recommendation: 'Suitable for general browsing and downloads'
    };
  } else if (responseTime < 400) {
    return {
      level: 'NORMAL',
      score: 60,
      emoji: '👍',
      description: 'Average connection speed',
      recommendation: 'Works for basic tasks but may have delays'
    };
  } else if (responseTime < 800) {
    return {
      level: 'SLOW',
      score: 40,
      emoji: '🐌',
      description: 'Below average connection with noticeable latency',
      recommendation: 'Consider checking your network or proxy settings'
    };
  } else {
    return {
      level: 'VERY SLOW',
      score: 20,
      emoji: '🐢',
      description: 'Poor connection with high latency',
      recommendation: 'Network optimization strongly recommended'
    };
  }
}

function detectProxy(headers) {
  const proxyHeaders = [
    'x-forwarded-for',
    'x-forwarded-host',
    'x-forwarded-proto',
    'via',
    'x-real-ip',
    'forwarded'
  ];
  
  return proxyHeaders.some(header => headers[header] !== undefined);
}
