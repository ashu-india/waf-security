import { useState } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { MLTrainingDashboard } from '@/components/ml-training-dashboard';
import { MLFeedbackForm } from '@/components/ml-feedback-form';
import { MLModelVersions } from '@/components/ml-model-versions';
import { Brain, MessageSquare, GitBranch } from 'lucide-react';

export default function MLDashboardPage() {
  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-3xl font-bold">ML Model Management</h1>
        <p className="text-gray-600 mt-1">
          Train, monitor, and improve your threat detection model with real-time metrics and feedback.
        </p>
      </div>

      <Tabs defaultValue="training" className="space-y-4">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="training" className="flex items-center gap-2">
            <Brain className="h-4 w-4" />
            <span className="hidden sm:inline">Training</span>
          </TabsTrigger>
          <TabsTrigger value="feedback" className="flex items-center gap-2">
            <MessageSquare className="h-4 w-4" />
            <span className="hidden sm:inline">Feedback</span>
          </TabsTrigger>
          <TabsTrigger value="versions" className="flex items-center gap-2">
            <GitBranch className="h-4 w-4" />
            <span className="hidden sm:inline">Versions</span>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="training" className="space-y-4">
          <MLTrainingDashboard />
        </TabsContent>

        <TabsContent value="feedback" className="space-y-4">
          <MLFeedbackForm />
        </TabsContent>

        <TabsContent value="versions" className="space-y-4">
          <MLModelVersions />
        </TabsContent>
      </Tabs>
    </div>
  );
}
