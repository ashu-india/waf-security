/**
 * Challenge verification endpoints
 * Local CAPTCHA without external services
 */

import { Router } from 'express';
import { generateChallenge, verifyChallenge, getChallenge } from '../utils/captcha';

const router = Router();

// Store bypass tokens in memory
const bypassTokens = new Map<string, { ip: string; expiresAt: Date; requestId: string }>();

/**
 * Generate random token
 */
function generateToken(): string {
  return Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
}

/**
 * GET /api/waf/challenge - Generate new CAPTCHA challenge
 */
router.get('/challenge', (req, res) => {
  try {
    const { id, question } = generateChallenge();
    
    res.json({
      success: true,
      challengeId: id,
      question: question,
      hint: 'Solve the math problem above',
      ttl: 600, // 10 minutes
    });
  } catch (error) {
    console.error('Challenge generation error:', error);
    res.status(500).json({ error: 'Failed to generate challenge' });
  }
});

/**
 * POST /api/waf/verify-challenge - Verify CAPTCHA answer
 */
router.post('/verify-challenge', (req, res) => {
  try {
    const { challengeId, answer, requestId } = req.body;
    const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';

    if (!challengeId || !answer) {
      return res.status(400).json({
        error: 'Missing challengeId or answer',
      });
    }

    // Verify CAPTCHA
    const verification = verifyChallenge(challengeId, answer);

    if (!verification.success) {
      return res.status(400).json({
        success: false,
        message: verification.message,
        error: verification.error,
      });
    }

    // Generate bypass token valid for 10 minutes
    const token = generateToken();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    
    bypassTokens.set(token, {
      ip: clientIp,
      expiresAt,
      requestId: requestId || 'unknown',
    });

    res.json({
      success: true,
      message: 'Challenge passed! You can now retry your request.',
      bypassToken: token,
      expiresIn: 600,
    });
  } catch (error) {
    console.error('Challenge verification error:', error);
    res.status(500).json({ error: 'Verification service error' });
  }
});

/**
 * GET /api/waf/challenge/:id - Get challenge question
 */
router.get('/challenge/:id', (req, res) => {
  try {
    const challenge = getChallenge(req.params.id);

    if (!challenge) {
      return res.status(404).json({
        error: 'Challenge not found or expired',
      });
    }

    res.json({
      success: true,
      question: challenge.question,
    });
  } catch (error) {
    console.error('Challenge retrieval error:', error);
    res.status(500).json({ error: 'Failed to retrieve challenge' });
  }
});

/**
 * Verify bypass token (used internally)
 */
export function verifyBypassToken(token: string, ip: string): boolean {
  const tokenData = bypassTokens.get(token);
  
  if (!tokenData) {
    return false;
  }

  // Check if expired
  if (new Date() > tokenData.expiresAt) {
    bypassTokens.delete(token);
    return false;
  }

  // Check if IP matches
  if (tokenData.ip !== ip) {
    return false;
  }

  // Token is valid
  return true;
}

/**
 * Cleanup expired tokens (call periodically)
 */
function cleanupExpiredTokens(): number {
  const now = new Date();
  let cleaned = 0;
  
  for (const [token, data] of bypassTokens.entries()) {
    if (data.expiresAt < now) {
      bypassTokens.delete(token);
      cleaned++;
    }
  }
  
  return cleaned;
}

// Run cleanup every 5 minutes
setInterval(() => {
  const cleaned = cleanupExpiredTokens();
  if (cleaned > 0) {
    console.log(`[CAPTCHA] Cleaned up ${cleaned} expired bypass tokens`);
  }
}, 5 * 60 * 1000);

export default router;
