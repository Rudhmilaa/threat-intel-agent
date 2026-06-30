import useSWR, { mutate } from 'swr';

export interface EnvVariable {
    name: string;
    display_name: string;
    value: string;
    raw_value?: string | null;
    description: string;
    type: 'string' | 'boolean' | 'number' | 'url' | 'email';
    default: string;
    required: boolean;
    sensitive: boolean;
    editable: boolean;
    action_trigger?: string | null;
    group: string;
    validation: Record<string, any>;
}

export interface EnvVariablesResponse {
    data: EnvVariable[];
    metadata: {
        total: number;
        file_path: string;
    };
}

export interface UpdateVariablesRequest {
    variables: Record<string, string | boolean | number>;
}

export interface UpdateVariablesResponse {
    data: {
        updated: number;
        variables: string[];
        actions: Array<{
            action: string;
            variable: string;
            status: 'success' | 'warning' | 'error' | 'pending';
            message: string;
        }>;
    };
}

const fetcher = async (url: string): Promise<EnvVariablesResponse> => {
    const response = await fetch(url);
    if (!response.ok) {
        const error: any = new Error(`Failed to fetch environment variables: ${response.status}`);
        error.status = response.status;
        error.statusText = response.statusText;
        throw error;
    }
    return response.json();
};

export function useStingarEnv() {
    const { data, error, mutate: swrMutate, isLoading } = useSWR(
        '/api/settings/env',
        fetcher,
        {
            revalidateOnFocus: false,
            revalidateOnReconnect: true,
            dedupingInterval: 5000,
            errorRetryCount: 3,
            errorRetryInterval: 5000,
            keepPreviousData: true,
            shouldRetryOnError: (error) => {
                // Retry on all errors - 401 might be transient if Apiarist isn't ready yet
                return true;
            },
            onErrorRetry: (error, key, config, revalidate, { retryCount }) => {
                if (retryCount >= (config.errorRetryCount || 3)) {
                    return;
                }
                const baseDelay = config.errorRetryInterval || 5000;
                const waitTime = error?.status === 401 
                    ? Math.min(baseDelay * Math.pow(2, retryCount), 10000)
                    : baseDelay;
                setTimeout(() => revalidate({ retryCount }), waitTime);
            },
        }
    );

    const updateVariables = async (updates: Record<string, string | boolean | number>): Promise<UpdateVariablesResponse> => {
        const response = await fetch('/api/settings/env', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(updates),
        });

        if (!response.ok) {
            const errorText = await response.text();
            const error: any = new Error(`Failed to update variables: ${response.status}`);
            error.status = response.status;
            error.statusText = response.statusText;
            error.details = errorText;
            throw error;
        }

        const result = await response.json();
        
        // Invalidate cache to refetch updated values
        await swrMutate();
        
        return result;
    };

    return {
        variables: data?.data ?? [],
        metadata: data?.metadata,
        isLoading,
        error: error || null,
        refetch: swrMutate,
        updateVariables,
    };
}

export function useStingarEnvVariable(variableName: string) {
    const { data, error, mutate, isLoading } = useSWR(
        variableName ? `/api/settings/env/${variableName}` : null,
        async (url: string) => {
            const response = await fetch(url);
            if (!response.ok) {
                const error: any = new Error(`Failed to fetch variable: ${response.status}`);
                error.status = response.status;
                error.statusText = response.statusText;
                throw error;
            }
            return response.json();
        },
        {
            revalidateOnFocus: false,
            dedupingInterval: 5000,
            errorRetryCount: 3,
            errorRetryInterval: 5000,
        }
    );

    return {
        variable: data?.data,
        isLoading,
        error: error || null,
        refetch: mutate,
    };
}

