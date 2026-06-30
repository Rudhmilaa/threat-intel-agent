export interface HoneypotStore {
  id: number;
  name: string;
  description: string;
  category: string;
  hpType: string;
  status: string;
  rating: number;
  downloads: number;
  tags: string[];
  author: string;
  version: string;
  createdAt: string;
  updatedAt: string;
  configuration: any;
  requirements: string[];
  installationStatus?: InstallationStatus;
  // Enhanced fields for dynamic configuration
  parsedPorts?: Array<{
    protocol: string;
    port: number;
    external?: number;
    internal?: number;
  }>;
  parsedProtocols?: string[];
  configurationSchema?: any;
  defaultConfiguration?: any;
  supportedProtocols?: string[];
  defaultPorts?: number[];
  // Data source and staleness information
  dataSource?: 'remote' | 'cache';
  lastUpdated?: string;
  isStale?: boolean;
  ageHours?: number;
}

export interface InstallationStatus {
  id: number;
  remoteHoneypotId: number;
  status: 'installed' | 'installing' | 'failed' | 'updating';
  installedAt: string;
  updatedAt: string;
  configuration: any;
  hostId?: string;
  deploymentId?: string;
}

export interface StorePagination {
  page: number;
  perPage: number;
  total: number;
  pages: number;
}

export interface StoreFilters {
  category?: string;
  hpType?: string;
  status?: string;
  tags?: string;
  minRating?: number;
}

export interface StoreResponse<T> {
  data: T;
  pagination?: StorePagination;
  filters?: StoreFilters;
  source?: 'remote' | 'cache';
}

export interface Category {
  id: number;
  name: string;
  description: string;
  honeypotCount: number;
}

export interface Tag {
  id: number;
  name: string;
  description: string;
  honeypotCount: number;
}

export interface StoreStats {
  totalHoneypots: number;
  totalCategories: number;
  totalDownloads: number;
  averageRating: number;
  recentlyAdded: number;
  topCategories: Array<{
    name: string;
    count: number;
  }>;
}

export interface InstallationData {
  hostId?: string;
  configuration?: any;
  autoDeploy?: boolean;
}
