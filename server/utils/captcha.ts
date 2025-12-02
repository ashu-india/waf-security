/**
 * Local CAPTCHA implementation
 * Math-based challenge without external services
 */

interface ChallengeData {
  id: string;
  num1: number;
  num2: number;
  operation: '+' | '-' | '*';
  question: string;
  answer: number;
  createdAt: Date;
  expiresAt: Date;
  attempts: number;
}

// Store challenges in memory (limit to 10,000 for safety)
const challenges = new Map<string, ChallengeData>();
const MAX_CHALLENGES = 10000;
const CHALLENGE_TTL = 10 * 60 * 1000; // 10 minutes
const MAX_ATTEMPTS = 5;

/**
 * Generate a random math challenge
 */
export function generateChallenge(): { id: string; question: string } {
  // Generate two random numbers (1-20)
  const num1 = Math.floor(Math.random() * 20) + 1;
  const num2 = Math.floor(Math.random() * 20) + 1;
  
  // Choose random operation
  const operations: Array<'+' | '-' | '*'> = ['+', '-', '*'];
  const operation = operations[Math.floor(Math.random() * operations.length)];
  
  // Calculate answer
  let answer: number;
  let question: string;
  
  switch (operation) {
    case '+':
      answer = num1 + num2;
      question = `${num1} + ${num2}`;
      break;
    case '-':
      // Ensure positive result
      answer = Math.abs(num1 - num2);
      question = `${Math.max(num1, num2)} - ${Math.min(num1, num2)}`;
      break;
    case '*':
      answer = num1 * num2;
      question = `${num1} × ${num2}`;
      break;
  }
  
  // Generate unique ID
  const id = Math.random().toString(36).substring(2, 11);
  
  // Clean up old challenges if too many stored
  if (challenges.size > MAX_CHALLENGES) {
    const now = new Date();
    for (const [key, challenge] of challenges.entries()) {
      if (challenge.expiresAt < now) {
        challenges.delete(key);
      }
    }
  }
  
  // Store challenge
  const now = new Date();
  challenges.set(id, {
    id,
    num1,
    num2,
    operation,
    question,
    answer,
    createdAt: now,
    expiresAt: new Date(now.getTime() + CHALLENGE_TTL),
    attempts: 0,
  });
  
  return { id, question };
}

/**
 * Verify challenge answer
 */
export function verifyChallenge(id: string, answer: string): {
  success: boolean;
  message: string;
  error?: string;
} {
  const challenge = challenges.get(id);
  
  if (!challenge) {
    return { success: false, message: 'Challenge not found', error: 'invalid_challenge' };
  }
  
  if (new Date() > challenge.expiresAt) {
    challenges.delete(id);
    return { success: false, message: 'Challenge expired', error: 'expired' };
  }
  
  challenge.attempts++;
  
  if (challenge.attempts > MAX_ATTEMPTS) {
    challenges.delete(id);
    return { success: false, message: 'Too many attempts', error: 'too_many_attempts' };
  }
  
  // Parse answer
  const userAnswer = parseInt(answer, 10);
  
  if (isNaN(userAnswer)) {
    return { success: false, message: 'Invalid answer format' };
  }
  
  if (userAnswer === challenge.answer) {
    challenges.delete(id);
    return { success: true, message: 'Challenge passed' };
  }
  
  return {
    success: false,
    message: 'Incorrect answer. Please try again.',
    error: 'incorrect_answer',
  };
}

/**
 * Get challenge info (for frontend)
 */
export function getChallenge(id: string): { question: string } | null {
  const challenge = challenges.get(id);
  
  if (!challenge) {
    return null;
  }
  
  if (new Date() > challenge.expiresAt) {
    challenges.delete(id);
    return null;
  }
  
  return { question: challenge.question };
}

/**
 * Cleanup expired challenges (call periodically)
 */
export function cleanupExpiredChallenges(): number {
  const now = new Date();
  let cleaned = 0;
  
  for (const [key, challenge] of challenges.entries()) {
    if (challenge.expiresAt < now) {
      challenges.delete(key);
      cleaned++;
    }
  }
  
  return cleaned;
}

// Run cleanup every 5 minutes
setInterval(() => {
  const cleaned = cleanupExpiredChallenges();
  if (cleaned > 0) {
    console.log(`[CAPTCHA] Cleaned up ${cleaned} expired challenges`);
  }
}, 5 * 60 * 1000);
