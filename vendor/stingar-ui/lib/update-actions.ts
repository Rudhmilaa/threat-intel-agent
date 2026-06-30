'use server';

// Normalize API_HOST by removing trailing slash if present
const API_HOST_RAW = process.env.API_HOST || 'http://localhost:8000';
const API_HOST = API_HOST_RAW.replace(/\/+$/, ''); // Remove trailing slashes
const API_URL = `${API_HOST}/api/v2`;
const API_KEY = process.env.API_KEY || '';

export interface SystemVersion {
    version: string;
    version_state_file?: string;
    compose_file?: string;
    installed_date?: string;
    last_check?: string;
    images_pulled?: boolean;
    images_pulled_date?: string;
}

export interface UpdateCheckResponse {
    current_version: string | null;
    latest_version: string;
    update_available: boolean;
    within_update_window: boolean;
    update_window: {
        start: string;
        end: string;
    };
    latest_version_info?: {
        version: string;
        release_date?: string;
        docker_images?: Record<string, string>;
        mandatory?: boolean;
        breaking_changes?: boolean;
        changelog?: string;
        release_notes?: string;
        release_notes_url?: string;
        update_instructions?: string;
    };
}

export interface LatestVersionInfo {
    version: string;
    release_notes?: string;
    release_notes_url?: string;
    changelog?: string;
    docker_images?: Record<string, string>;
}

export interface UpdateStatusResponse {
    service_enabled: boolean;
    remote_store_enabled: boolean;
    current_version: string | null;
    latest_version: string | null;
    update_available: boolean;
    latest_version_info?: LatestVersionInfo | null;
    check_interval: number;
    update_window: {
        start: string;
        end: string;
        within_window: boolean;
    };
    compose_file: string;
    version_state_file: string;
}

export interface UpdateApplyResponse {
    job_id: string;
    message: string;
    current_version: string | null;
    target_version: string;
}

export interface UpdateJobStatus {
    job_id: string;
    status: 'pending' | 'in-progress' | 'completed' | 'failed';
    current_version: string | null;
    target_version: string;
    created_at: string;
    updated_at: string;
    error?: string | null;
    steps?: Array<{
        step: string;
        message: string;
        timestamp: string;
        error?: string | null;
    }>;
    rolled_back?: boolean;
}

export interface UpdateSettings {
    update_mode: 'manual' | 'auto';
    update_window_start: string;
    update_window_end: string;
    check_interval: number;
    service_enabled: boolean;
    compose_file?: string;
    cleanup_old_images: boolean;
    cleanup_after_hours: number;
}

async function fetchWithAuth(endpoint: string, options: RequestInit = {}) {
    const response = await fetch(`${API_URL}${endpoint}`, {
        ...options,
        headers: {
            'API-KEY': API_KEY || '',
            'Content-Type': 'application/json',
            ...options.headers,
        },
        cache: 'no-cache',
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`API request failed: ${response.status} ${response.statusText}: ${errorText}`);
    }

    return response.json();
}

export async function getSystemVersion(): Promise<SystemVersion> {
    return fetchWithAuth('/system/version');
}

export async function checkForUpdates(): Promise<UpdateCheckResponse> {
    return fetchWithAuth('/system/update-check');
}

export async function getUpdateStatus(): Promise<UpdateStatusResponse> {
    return fetchWithAuth('/system/update-status');
}

export async function applyUpdate(): Promise<UpdateApplyResponse> {
    return fetchWithAuth('/system/update/apply', {
        method: 'POST',
    });
}

export async function getUpdateJobStatus(jobId: string): Promise<UpdateJobStatus> {
    return fetchWithAuth(`/system/update/status/${jobId}`);
}

export async function getUpdateSettings(): Promise<UpdateSettings> {
    return fetchWithAuth('/settings/update');
}

export async function updateUpdateSettings(settings: Partial<UpdateSettings>): Promise<{ message: string; settings: UpdateSettings }> {
    return fetchWithAuth('/settings/update', {
        method: 'PUT',
        body: JSON.stringify(settings),
    });
}

