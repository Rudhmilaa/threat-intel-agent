/**
 * Honeypot Request models for TypeScript
 */

export type RequestStatus = 
  | 'pending'
  | 'in_review'
  | 'approved'
  | 'rejected'
  | 'in_development'
  | 'completed';

export type RequestPriority = 'low' | 'medium' | 'high' | 'critical';

export type IPProtocol = 'IPv4' | 'IPv6';

export interface HoneypotRequest {
  id: number;
  requestId: string;
  title: string;
  description: string;
  requesterName?: string;
  requesterEmail?: string;
  requesterOrganization?: string;
  status: RequestStatus;
  priority: RequestPriority;
  category?: string;
  requiredPorts: number[];
  supportedProtocols: string[];
  ipProtocolSupport: IPProtocol[];
  cves: string[];
  additionalRequirements?: string;
  tags: string[];
  useCases?: string;
  expectedBehavior?: string;
  securityConsiderations?: string;
  votes: number;
  commentsCount: number;
  createdAt: string;
  updatedAt: string;
  submittedBy?: string;
  reviewedBy?: string;
  reviewedAt?: string;
  reviewNotes?: string;
}

export interface HoneypotRequestCreate {
  title: string;
  description: string;
  requesterName: string;
  requesterEmail: string;
  requesterOrganization?: string;
  category?: string;
  priority?: RequestPriority;
  requiredPorts: number[];
  supportedProtocols: string[];
  ipProtocolSupport: IPProtocol[];
  cves: string[];
  additionalRequirements?: string;
  tags: string[];
  useCases?: string;
  expectedBehavior?: string;
  securityConsiderations?: string;
  submittedBy?: string;
}

