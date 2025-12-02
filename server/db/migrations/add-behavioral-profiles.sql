-- Add behavioral_profiles table for persistent storage of login profiles
CREATE TABLE IF NOT EXISTS behavioral_profiles (
  id VARCHAR(36) PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  tenant_id VARCHAR(36),
  total_attempts INTEGER DEFAULT 0,
  failed_attempts INTEGER DEFAULT 0,
  successful_attempts INTEGER DEFAULT 0,
  last_attempt TIMESTAMP,
  is_locked BOOLEAN DEFAULT FALSE,
  lock_expires_at TIMESTAMP,
  bot_score REAL DEFAULT 0,
  anomaly_score REAL DEFAULT 0,
  risk_level VARCHAR(20) DEFAULT 'low',
  ips_json JSONB,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_email (email),
  INDEX idx_tenant_id (tenant_id),
  INDEX idx_risk_level (risk_level)
);

-- Add behavioral_events table for historical tracking
CREATE TABLE IF NOT EXISTS behavioral_events (
  id VARCHAR(36) PRIMARY KEY,
  profile_id VARCHAR(36) NOT NULL REFERENCES behavioral_profiles(id) ON DELETE CASCADE,
  email VARCHAR(255) NOT NULL,
  event_type VARCHAR(50) NOT NULL,
  ip_address VARCHAR(45),
  user_agent TEXT,
  success BOOLEAN,
  score REAL,
  reason TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_profile_id (profile_id),
  INDEX idx_email (email),
  INDEX idx_created_at (created_at)
);
