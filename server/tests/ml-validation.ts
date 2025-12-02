import fetch from 'node-fetch';
import * as fs from 'fs';
import * as path from 'path';

const BASE_URL = 'http://localhost:5000/api';
const ADMIN_TOKEN = 'test-admin'; // Will be set via auth

interface TestResult {
  name: string;
  passed: boolean;
  error?: string;
  duration: number;
}

const results: TestResult[] = [];

async function test(name: string, fn: () => Promise<void>) {
  const start = Date.now();
  try {
    await fn();
    results.push({ name, passed: true, duration: Date.now() - start });
    console.log(`✅ ${name} (${Date.now() - start}ms)`);
  } catch (error) {
    results.push({
      name,
      passed: false,
      error: error instanceof Error ? error.message : String(error),
      duration: Date.now() - start,
    });
    console.log(`❌ ${name}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function runTests() {
  console.log('🧪 Phase 6: ML Pipeline Testing & Validation\n');

  // Test 1: Verify scheduler is running
  await test('Scheduler Status - Verify scheduler initialized', async () => {
    const res = await fetch(`${BASE_URL}/ml/scheduler/status`, {
      credentials: 'include',
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as any;
    if (!data.jobs) throw new Error('No jobs in response');
    if (data.jobs.length < 2) throw new Error('Expected at least 2 jobs (daily, weekly)');
    console.log(`   Found ${data.jobs.length} scheduled jobs`);
  });

  // Test 2: Trigger training
  let trainedModelId: string;
  await test('Training Pipeline - Start model training', async () => {
    const res = await fetch(`${BASE_URL}/ml/train`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    const data = (await res.json()) as any;
    if (!data.modelId) throw new Error('No modelId returned');
    trainedModelId = data.modelId;
    console.log(`   Trained model ID: ${trainedModelId}`);
  });

  // Test 3: Verify model persistence
  await test('Model Persistence - Verify model saved to disk', async () => {
    const modelPath = path.join(process.cwd(), 'server', 'ml-models', trainedModelId);
    if (!fs.existsSync(modelPath)) {
      throw new Error(`Model directory not found at ${modelPath}`);
    }
    const files = fs.readdirSync(modelPath);
    if (files.length === 0) throw new Error('Model directory is empty');
    console.log(`   Model files: ${files.join(', ')}`);
  });

  // Test 4: Get trained model metrics
  await test('Model Evaluation - Retrieve model metrics', async () => {
    const res = await fetch(`${BASE_URL}/ml/metrics`, {
      credentials: 'include',
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as any;
    if (!data.model) throw new Error('No model metrics in response');
    if (typeof data.model.accuracy !== 'number') throw new Error('Invalid accuracy metric');
    console.log(`   Model accuracy: ${(data.model.accuracy * 100).toFixed(1)}%`);
  });

  // Test 5: List all model versions
  await test('Model Versions - List saved versions', async () => {
    const res = await fetch(`${BASE_URL}/ml/models`, {
      credentials: 'include',
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as any;
    if (!data.models) throw new Error('No models list in response');
    if (data.models.length === 0) throw new Error('No trained models found');
    console.log(`   Total models: ${data.models.length}`);
  });

  // Test 6: Submit feedback
  await test('Feedback System - Submit training feedback', async () => {
    const res = await fetch(`${BASE_URL}/ml/feedback`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        requestId: 'test-req-001',
        actualLabel: 1,
        predictedLabel: 0,
        tenantId: 'default',
        confidence: 0.95,
        notes: 'Test false negative',
      }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    const data = (await res.json()) as any;
    if (!data.id) throw new Error('No feedback ID returned');
  });

  // Test 7: Retrieve feedback stats
  await test('Feedback Statistics - Verify feedback integrated', async () => {
    const res = await fetch(`${BASE_URL}/ml/feedback/stats`, {
      credentials: 'include',
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as any;
    if (data.feedback.totalLabeled < 1) throw new Error('No feedback labels found');
    console.log(`   Total labels: ${data.feedback.totalLabeled}`);
  });

  // Test 8: Verify no model loading errors on startup
  await test('Startup Validation - No errors in model loading', async () => {
    const res = await fetch(`${BASE_URL}/ml/metrics`, {
      credentials: 'include',
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    // If we got here, server is running and model loaded successfully
  });

  // Summary
  console.log('\n📊 Test Results Summary:');
  console.log(`Total Tests: ${results.length}`);
  const passed = results.filter((r) => r.passed).length;
  const failed = results.filter((r) => !r.passed).length;
  console.log(`✅ Passed: ${passed}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`⏱️  Total Time: ${results.reduce((sum, r) => sum + r.duration, 0)}ms`);

  if (failed > 0) {
    console.log('\n❌ Failed Tests:');
    results.filter((r) => !r.passed).forEach((r) => {
      console.log(`  - ${r.name}: ${r.error}`);
    });
    process.exit(1);
  } else {
    console.log('\n✅ All tests passed!');
    process.exit(0);
  }
}

// Run tests
runTests().catch((err) => {
  console.error('Test suite error:', err);
  process.exit(1);
});
