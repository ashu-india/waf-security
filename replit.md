# WAF Admin Dashboard

## Overview
This project is a multi-tenant Web Application Firewall (WAF) administration dashboard for real-time monitoring, threat detection, and policy management across multiple websites. It offers live traffic analysis, OWASP-compliant rules, customizable security policies, and comprehensive analytics, including behavioral and geo-location insights. The system incorporates enterprise-grade ML for threat scoring and bot detection, multi-tenant DDoS protection, and a WAF vs. ModSecurity comparison tool. The primary goal is to provide a scalable, user-friendly web security solution with actionable intelligence, including comprehensive compliance management for frameworks like GDPR, HIPAA, SOC2, PCI-DSS, ISO27001, NIST, and CIS.

## User Preferences
Preferred communication style: Simple, everyday language.
Preferred mode: Fast mode for quick, focused edits.

## System Architecture

### Frontend
The frontend utilizes React 18, TypeScript, and Vite, with Wouter for routing. UI components are built using `shadcn/ui` (Radix UI, Tailwind CSS) with light/dark mode support. TanStack Query manages server state, and Server-Sent Events (SSE) provide real-time updates. The UI includes dynamic filtering, batch management for WAF rules, and a complete avatar system.

### Backend
The backend is an Express.js application (TypeScript) featuring session-based authentication (Passport.js) and CORS. RESTful APIs are secured with role-based authorization, rate limiting, and Zod validation. A custom WAF engine performs pattern matching, threat scoring, geo-location checks, behavioral analysis, regional rate limiting, and VPN detection, integrating with a reverse proxy. Real-time traffic is streamed via an SSE server. Compliance management is integrated with models for frameworks, rules, tenant-specific selections, and audit trails.

### Data Storage
SQLite is used as the sole database with Sequelize ORM. The database schema supports users, tenants, policies, WAF rules, requests, analysis, alerts, overrides, webhooks, IP lists, DDoS events, audit files, analytics aggregates, behavioral profiles and events, and comprehensive compliance management.

### Authentication & Authorization
Email-based authentication uses Passport.js LocalStrategy and Express sessions with secure cookies. Role-based authorization supports Admin, Operator, and Viewer roles. Security features include rate limiting on login attempts, input sanitization, CSRF, and XSS protection.

### Core Features
-   **WAF Engine:** Implements OWASP rules (SQLi, XSS, RCE), IP reputation, rate/header anomaly detection, deep payload inspection, geo-location blocking, regional rate limiting, and VPN detection.
-   **Behavioral Analysis:** Detects credential stuffing, bot attacks, and ML-based anomalies.
-   **DDoS Protection:** Tenant-based detection with graduated response and real-time monitoring.
-   **ML Infrastructure:** Services for model persistence, evaluation, training, and automated scheduling.
-   **Policy Management:** UI for creating and managing security policies, including behavioral rules, enforcement modes, block/challenge thresholds, rate limits, geo-location/VPN settings, and per-tenant WAF engine selection.
-   **Dashboard & Analytics:** KPIs, live traffic, attack visualizations, security scorecards, and detailed analytics.
-   **Compliance Management:** Comprehensive seeding and mapping of 224 compliance rules across 7 frameworks (GDPR, HIPAA, SOC2, PCI-DSS, ISO27001, NIST, CIS), with per-tenant framework selection, audit capabilities, real-time monitoring, and alerting.

## External Dependencies

### Database & ORM
-   **Sequelize:** ORM
-   **SQLite:** File-based database

### UI Libraries
-   **Radix UI:** Headless component primitives
-   **Recharts:** Charting library
-   **date-fns:** Date manipulation utility
-   **Lucide React:** Icon library

### Real-time Communication
-   **Server-Sent Events (SSE):** For live data updates

### Form Handling & Validation
-   **react-hook-form:** Form state management
-   **Zod:** Schema validation library

### Geo-Location & IP Intelligence
-   **geoip-lite:** Fast IP-to-country lookups

### Third-party Integrations
-   **Webhook system:** For external alerts and notifications

### ML Libraries
-   **scikit-learn:** Machine Learning model training
-   **joblib:** Model serialization
-   **numpy & pandas:** Data processing and manipulation
## Phase 6: Automated Compliance Remediation & Actions - COMPLETE (Dec 2, 2025) ✅

**Files:**
- `server/services/compliance-remediation.ts` - Remediation service
- `server/api/compliance-remediation-endpoints.ts` - Remediation API
- `client/src/pages/compliance-remediation.tsx` - Remediation dashboard

**Routes:**
- `/compliance/remediation` - Remediation actions and history

**Backend Service: ComplianceRemediationService**
- `generateRemediationActions()` - Generate corrective actions for low compliance
- `executeRemediationAction()` - Execute specific remediation action
- `enableMissingRules()` - Auto-enable missing compliance rules
- `updateTenantPolicy()` - Update policies with compliance requirements
- `enforceStrictMode()` - Activate strict compliance enforcement
- `getRemediationHistory()` - Retrieve remediation history
- `scheduleAutomatedRemediation()` - Schedule periodic remediation checks

**API Endpoints (4 new):**
1. `POST /api/compliance-remediation/generate` - Generate remediation actions
2. `POST /api/compliance-remediation/execute` - Execute a remediation action
3. `GET /api/compliance-remediation/tenant/:tenantId/history` - Get remediation history
4. `POST /api/compliance-remediation/schedule` - Schedule automated remediation

**Remediation Action Types:**
- `enable_rule` - Automatically enable missing compliance rules
- `update_policy` - Update security policy with compliance requirements
- `enforce_strict` - Activate strict compliance mode (critical situations)
- `manual_review` - Flag for manual compliance review

**Action Status Flow:**
- `pending` - Awaiting execution
- `in_progress` - Currently executing
- `completed` - Successfully executed
- `failed` - Execution failed

**Dashboard Features:**
- View all remediation actions (pending, in-progress, completed)
- Execute pending actions with one click
- Track affected rules per action
- View execution results and timestamps
- Statistics on completed/pending/failed actions
- Detailed remediation type descriptions

### Status: ✅ Phase 6 COMPLETE & TESTED

## Phase 7: Compliance Webhooks & Notifications - COMPLETE (Dec 2, 2025) ✅

**Files:**
- `server/services/compliance-webhooks.ts` - Webhook management and dispatch
- `server/api/compliance-webhooks-endpoints.ts` - Webhook API endpoints
- `client/src/pages/compliance-webhooks.tsx` - Webhook configuration UI

**Routes:**
- `/compliance/webhooks` - Webhook management dashboard

**Backend Service: ComplianceWebhookService**
- `registerWebhook()` - Register new webhook endpoint
- `getWebhooks()` - List tenant webhooks
- `updateWebhook()` - Update webhook configuration
- `deleteWebhook()` - Remove webhook
- `sendWebhookEvent()` - Dispatch events to webhooks
- `testWebhook()` - Test webhook connectivity
- `getWebhookHistory()` - Get delivery history
- `triggerComplianceAlert()` - Send alert events
- `triggerRemediationAction()` - Send remediation events
- `triggerAuditLog()` - Send audit events

**API Endpoints (5 new):**
1. `POST /api/compliance-webhooks/register` - Register webhook
2. `GET /api/compliance-webhooks/tenant/:tenantId` - List webhooks
3. `PUT /api/compliance-webhooks/:webhookId` - Update webhook
4. `DELETE /api/compliance-webhooks/:webhookId` - Delete webhook
5. `POST /api/compliance-webhooks/:webhookId/test` - Test webhook
6. `GET /api/compliance-webhooks/:webhookId/history` - Get delivery history

**Webhook Events:**
- `compliance_alert` - Triggered on compliance score drops
- `remediation_action` - Triggered when remediation executes
- `audit_log` - Triggered on compliance audit actions

**Webhook Features:**
- HMAC-SHA256 signature verification
- Automatic retry with exponential backoff (configurable)
- Delivery history tracking (last 100 events)
- Test webhook connectivity
- Subscribe to specific event types
- Active/inactive toggle

**Webhook Payload Format:**
```json
{
  "event": "compliance_alert",
  "tenantId": "tenant-1",
  "timestamp": "2025-12-02T07:41:00Z",
  "data": {...},
  "signature": "sha256_hash"
}
```

**Dashboard Features:**
- Register new webhooks with URL and event selection
- Manage registered webhooks (edit, delete, test)
- View webhook delivery history
- Real-time event subscription
- HMAC signature support for security

### Status: ✅ Phase 7 COMPLETE & TESTED
