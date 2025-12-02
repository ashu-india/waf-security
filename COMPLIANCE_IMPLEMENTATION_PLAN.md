# Policy Compliance Implementation Plan
## Multi-Tenant WAF Rules Compliance System

---

## PHASE 1: Database Schema & Data Model (Backend)

### 1.1 New Database Tables

#### A. ComplianceFramework Table
```
- id (UUID, PK)
- name (string) - "GDPR", "HIPAA", "SOC2", "PCI-DSS", "ISO 27001", "NIST", "CIS"
- description (text)
- category (string) - "data-protection", "security", "infrastructure", "audit"
- region (string) - "EU", "US", "Global", "Industry-Specific"
- ruleCount (int) - total rules in framework
- createdAt (timestamp)
```

#### B. ComplianceRule Table (extends WafRule)
```
- id (UUID, PK)
- wafRuleId (FK to WafRule)
- complianceFrameworkId (FK to ComplianceFramework)
- complianceRuleId (string) - "GDPR-1.1", "HIPAA-5.2", etc.
- mappedCategory (string) - requirement category
- severity (string) - "mandatory", "recommended", "optional"
- description (text) - compliance requirement description
- proof (text) - how this rule proves compliance
- createdAt (timestamp)
```

#### C. TenantCompliance Table
```
- id (UUID, PK)
- tenantId (FK to Tenant)
- complianceFrameworkId (FK to ComplianceFramework)
- enabled (boolean) - is this compliance framework active?
- complianceStatus (enum) - "active", "in-review", "failed", "compliant"
- lastAuditDate (timestamp)
- nextAuditDate (timestamp)
- selectedRuleIds (JSON array) - rules tenant selected for this compliance
- enabledRuleIds (JSON array) - rules currently enabled
- createdAt (timestamp)
```

#### D. ComplianceAudit Table
```
- id (UUID, PK)
- tenantId (FK to Tenant)
- complianceFrameworkId (FK to ComplianceFramework)
- auditDate (timestamp)
- totalRequirements (int)
- metRequirements (int) - met compliance requirements
- failedRequirements (int)
- compliancePercentage (float) - 0-100
- failedRules (JSON array) - which rules/requirements failed
- actionItems (JSON array) - what needs to be fixed
- auditorNotes (text)
- createdAt (timestamp)
```

### 1.2 Sequelize Model Updates

**File: `server/models.ts`**

Add interfaces and models:
```typescript
- ComplianceFrameworkAttributes & ComplianceFramework class
- ComplianceRuleAttributes & ComplianceRule class
- TenantComplianceAttributes & TenantCompliance class
- ComplianceAuditAttributes & ComplianceAudit class
```

Add relationships:
```typescript
- ComplianceFramework.hasMany(ComplianceRule)
- ComplianceFramework.hasMany(TenantCompliance)
- WafRule.hasMany(ComplianceRule)
- Tenant.hasMany(TenantCompliance)
- Tenant.hasMany(ComplianceAudit)
```

---

## PHASE 2: Backend APIs

### 2.1 Compliance Framework Endpoints

**File: `server/routes.ts`**

```
GET /api/compliance/frameworks
  - List all compliance frameworks
  - Response: { id, name, description, ruleCount, region }

GET /api/compliance/frameworks/:id
  - Get framework details with all rules
  - Response: { framework, rules: [...] }

GET /api/tenants/:tenantId/compliance
  - List compliance status for tenant
  - Response: { frameworks: [{ framework, status, percentage, ... }] }

POST /api/tenants/:tenantId/compliance/:frameworkId/enable
  - Enable compliance framework for tenant
  - Body: { }

POST /api/tenants/:tenantId/compliance/:frameworkId/disable
  - Disable compliance framework
  - Body: { }

PATCH /api/tenants/:tenantId/compliance/:frameworkId/rules
  - Update selected/enabled rules for compliance
  - Body: { selectedRuleIds: [], enabledRuleIds: [] }

POST /api/tenants/:tenantId/compliance/:frameworkId/audit
  - Run compliance audit
  - Response: { auditResult, compliancePercentage, failedRules, ... }

GET /api/tenants/:tenantId/compliance/:frameworkId/audit-history
  - Get audit history
  - Response: { audits: [...] }
```

### 2.2 Compliance Checking Logic

**File: `server/compliance.ts` (NEW)**

```typescript
class ComplianceService {
  // Check which rules meet compliance requirements
  async checkComplianceStatus(tenantId, frameworkId)
  
  // Verify rules are enabled/properly configured
  async validateCompliance(tenantId, frameworkId, enabledRuleIds)
  
  // Calculate compliance percentage
  calculateCompliancePercentage(enabledRules, requiredRules)
  
  // Generate audit report
  async generateAuditReport(tenantId, frameworkId)
}
```

### 2.3 Database Seeding

**File: `server/db.ts` - Update seeding function**

Add compliance data:
```
- 7 Compliance Frameworks:
  * GDPR (Data Protection - EU)
  * HIPAA (Healthcare - US)
  * SOC2 (Security Audit - US)
  * PCI-DSS (Payment Card - Global)
  * ISO 27001 (Information Security - Global)
  * NIST (Cybersecurity - US)
  * CIS (Controls - Global)

- ~40-50 Compliance Rules per framework (280+ total)
- Each mapped to existing WAF rules or new rule requirements
```

**Compliance Framework Structure:**
```
GDPR Requirements:
├── GDPR-1: Data Security
│   ├── GDPR-1.1: Encryption at Rest (maps to WAF rule: encryption-check)
│   ├── GDPR-1.2: Encryption in Transit (maps to WAF rule: tls-check)
│   └── GDPR-1.3: Data Integrity (maps to WAF rule: data-integrity)
├── GDPR-2: Access Control
│   ├── GDPR-2.1: Authentication (maps to WAF rule: auth-bypass)
│   └── GDPR-2.2: Authorization (maps to WAF rule: privilege-escalation)
└── ... (7-8 main categories)

HIPAA Requirements:
├── HIPAA-1: Technical Safeguards
├── HIPAA-2: Physical Safeguards
├── ... etc

Similar structure for HIPAA, SOC2, PCI-DSS, ISO, NIST, CIS
```

---

## PHASE 3: Frontend UI Implementation

### 3.1 Compliance Rules Page Component

**File: `client/src/pages/compliance.tsx` (NEW)**

Layout:
```
1. Top Section: Framework Selector
   - Dropdown/tabs to select compliance framework
   - Shows: "GDPR" | "HIPAA" | "SOC2" | "PCI-DSS" | etc.

2. Compliance Dashboard
   - Compliance Score: "78/100 (78%)"
   - Status: "COMPLIANT" | "NON-COMPLIANT" | "IN-REVIEW"
   - Last Audit: "Dec 2, 2025"
   - Rules Met: "23/30"

3. Requirements List
   - Grouped by category (Data Security, Access Control, etc.)
   - Each requirement shows:
     * Requirement ID: "GDPR-1.1"
     * Description: "Implement encryption at rest"
     * Severity: "Mandatory" | "Recommended"
     * Status: ✓ Met | ✗ Not Met | ⚠ Partial
     * Rule(s): Show which WAF rules satisfy this
     * Toggle: Enable/Disable this requirement

4. Rules Table
   - Column: Requirement | Rule Name | Status | Action
   - Sort by compliance status
   - Filter by category, severity, status
   - Bulk actions: Enable All, Disable All

5. Compliance Report
   - Generate PDF/Download audit report
   - Show failed requirements
   - Recommendations to achieve compliance
```

### 3.2 Tenant Policy Integration

**File: `client/src/pages/policies.tsx` - UPDATE**

Add to Policy Details:
```
- "Compliance Frameworks" section
- Shows which compliance frameworks this policy enables
- Display: "GDPR: 78% | HIPAA: 85% | SOC2: 92%"
- Link to detailed compliance page
```

### 3.3 Rules Page Enhancement

**File: `client/src/pages/rules.tsx` - UPDATE**

Add compliance tagging:
```
- New column: "Compliance" shows which frameworks use this rule
  Example: "GDPR, HIPAA, PCI-DSS"
- Filter: "Compliance Framework" dropdown
  Shows rules mapped to selected compliance framework
- Badge: Shows rule is "GDPR Required", "ISO27001 Optional", etc.
```

### 3.4 Tenant Dashboard Widget

**File: `client/src/pages/dashboard.tsx` - UPDATE**

Add compliance card:
```
- "Compliance Status"
- Show all frameworks with current percentage
- Quick links to compliance pages
- Alert if compliance dropped below 80%
```

---

## PHASE 4: Multi-Tenant WAF Engine Integration

### 4.1 Update WAF Engine

**File: `server/waf-engine.ts` - UPDATE**

```typescript
class WafEngine {
  // Updated to load tenant-specific compliance rules
  async processTenantRequest(tenantId, request) {
    // Get tenant's enabled rules (respecting compliance selections)
    const enabledRules = await getTenantEnabledRules(tenantId);
    
    // Also load compliance-specific rules
    const complianceRules = await getTenantComplianceRules(tenantId);
    
    // Merge and process all applicable rules
    const allApplicableRules = mergeAndPrioritizeRules(
      enabledRules,
      complianceRules
    );
    
    // Continue normal WAF processing with merged rules
    const analysis = await analyzeRequest(request, allApplicableRules);
    
    return analysis;
  }
  
  // Track which compliance requirement each matched rule satisfies
  async trackComplianceViolation(tenantId, frameworkId, ruleId, violation) {
    // Log for compliance audit
  }
}
```

### 4.2 Tenant Rule Loading

**File: `server/storage.ts` - UPDATE**

```typescript
class StorageLayer {
  // Get all enabled rules for tenant (existing)
  getTenantEnabledRules(tenantId)
  
  // NEW: Get compliance-required rules for tenant
  async getTenantComplianceRules(tenantId) {
    const complianceFrameworks = await TenantCompliance.findAll({
      where: { tenantId, enabled: true }
    });
    
    const rules = [];
    for (const framework of complianceFrameworks) {
      const complianceRules = await ComplianceRule.findAll({
        where: { complianceFrameworkId: framework.complianceFrameworkId }
      });
      rules.push(...complianceRules);
    }
    
    return rules;
  }
}
```

---

## PHASE 5: Compliance Checking & Auditing

### 5.1 Compliance Audit Engine

**File: `server/compliance-audit.ts` (NEW)**

```typescript
class ComplianceAuditEngine {
  // Run audit for tenant against framework
  async auditTenantCompliance(tenantId, frameworkId) {
    // 1. Get all compliance requirements for framework
    const requirements = await getComplianceRequirements(frameworkId);
    
    // 2. Check which rules tenant has enabled
    const tenantRules = await getTenantEnabledRules(tenantId);
    
    // 3. Map requirements to rules
    const met = requirements.filter(req => 
      tenantRules.some(rule => rule.id === req.wafRuleId)
    );
    
    // 4. Calculate compliance percentage
    const percentage = (met.length / requirements.length) * 100;
    
    // 5. Generate report
    return {
      frameworkId,
      totalRequirements: requirements.length,
      metRequirements: met.length,
      failedRequirements: requirements.length - met.length,
      compliancePercentage: percentage,
      status: percentage >= 80 ? 'compliant' : 'non-compliant',
      failedRules: requirements.filter(req => !met.includes(req)),
      recommendations: generateRecommendations(failedRules)
    };
  }
  
  // Track compliance violations during WAF processing
  async logComplianceViolation(tenantId, frameworkId, ruleId, evidence) {
    // Store for audit trail
  }
}
```

### 5.2 Audit Report Generation

```typescript
class AuditReportService {
  async generatePdfReport(auditResult) {
    // Create professional PDF with:
    // - Compliance framework details
    // - Requirements met/not met
    // - Recommendations
    // - Timeline for remediation
  }
}
```

---

## PHASE 6: API Response Structure

### Sample Responses

**GET /api/compliance/frameworks**
```json
{
  "frameworks": [
    {
      "id": "gdpr-123",
      "name": "GDPR",
      "description": "General Data Protection Regulation",
      "ruleCount": 45,
      "region": "EU",
      "category": "data-protection"
    },
    {
      "id": "hipaa-456",
      "name": "HIPAA",
      "description": "Health Insurance Portability and Accountability Act",
      "ruleCount": 38,
      "region": "US",
      "category": "healthcare"
    }
  ]
}
```

**GET /api/compliance/frameworks/gdpr-123**
```json
{
  "framework": { /* framework details */ },
  "requirements": [
    {
      "id": "GDPR-1.1",
      "category": "Data Security",
      "description": "Implement encryption at rest",
      "severity": "mandatory",
      "proof": "Data must be encrypted using AES-256",
      "wafRules": [
        { "id": "rule-001", "name": "Encryption Check", "enabled": true }
      ]
    }
  ]
}
```

**GET /api/tenants/tenant-001/compliance**
```json
{
  "compliance": [
    {
      "framework": "GDPR",
      "enabled": true,
      "compliancePercentage": 78,
      "status": "in-review",
      "rulesRequired": 45,
      "rulesEnabled": 35,
      "lastAudit": "2025-12-02T10:30:00Z",
      "nextAudit": "2025-12-09T10:30:00Z"
    },
    {
      "framework": "HIPAA",
      "enabled": false,
      "compliancePercentage": 0,
      "status": "inactive"
    }
  ]
}
```

**POST /api/tenants/tenant-001/compliance/gdpr-123/audit**
```json
{
  "auditResult": {
    "frameworkId": "gdpr-123",
    "totalRequirements": 45,
    "metRequirements": 35,
    "failedRequirements": 10,
    "compliancePercentage": 77.78,
    "status": "non-compliant",
    "failedRules": [
      {
        "id": "GDPR-2.1",
        "description": "MFA enforcement",
        "severity": "mandatory",
        "recommendation": "Enable WAF rule: Multi-factor-auth-enforcement"
      }
    ],
    "auditDate": "2025-12-02T12:00:00Z",
    "nextRecommendedAudit": "2025-12-09T12:00:00Z"
  }
}
```

---

## PHASE 7: Implementation Order (Priority)

### Turn 1: Database & Backend Setup
1. Add 4 new database tables (ComplianceFramework, ComplianceRule, TenantCompliance, ComplianceAudit)
2. Create Sequelize models with relationships
3. Seed 7 compliance frameworks + 280 compliance rules
4. Create backend APIs (endpoints in routes.ts)
5. Create compliance service class

### Turn 2: WAF Engine Integration
1. Update WAF engine to load tenant compliance rules
2. Update storage layer to fetch compliance-required rules
3. Create compliance audit engine
4. Add compliance violation tracking

### Turn 3: Frontend UI
1. Create compliance page component
2. Add compliance framework selector
3. Show compliance dashboard with percentages
4. Add compliance tags to rules page
5. Add compliance widget to tenant dashboard
6. Update policies page with compliance info

### Turn 4: Testing & Refinement
1. Test multi-tenant compliance isolation
2. Verify audit calculations
3. Generate sample audit reports
4. Performance optimization

---

## Key Features Summary

✅ **Multi-Tenant Support**: Each tenant selects their compliance frameworks independently
✅ **7 Compliance Frameworks**: GDPR, HIPAA, SOC2, PCI-DSS, ISO27001, NIST, CIS
✅ **280+ Compliance Rules**: Mapped to WAF rules
✅ **Real-Time Compliance Checking**: WAF engine respects compliance rules
✅ **Audit Trail**: Track all compliance violations
✅ **Compliance Reporting**: Generate audit reports
✅ **Tenant Dashboard**: Show compliance status
✅ **Flexible Rule Management**: Enable/disable per compliance framework

---

## Database Growth

```
Current: 453 WAF rules + 5 tables
After Implementation:
- 453 WAF rules (existing)
- 280+ Compliance rules (new)
- 4 new tables (ComplianceFramework, ComplianceRule, TenantCompliance, ComplianceAudit)
- Total: ~750 rules in system
- Multi-tenant compliance tracking per framework
```
