import useSWR from "swr";
import { getBlocklist, getDeploymentLogs, getDeployments, getHosts, getKeys, getSensors, getSettings, getUser, getUsers } from "@/lib/actions";
import { getSessionsClient, getSessionClient } from "@/lib/client-sessions";


export function useUser() {
    const { data, error, isLoading, mutate } = useSWR("/user/me", getUser);
    return {
        user: data,
        isLoading: isLoading,
        error: error,
        mutate: mutate,
    };
}

export function useUsers() {
    const { data, error, isLoading, mutate } = useSWR("/users", getUsers);
    return {
        users: data,
        isLoading: isLoading,
        error: error,
        mutate: mutate,
    };
}

export function useHosts() {
    const { data, error, isLoading, mutate } = useSWR("/hosts", getHosts);
    return {
        hosts: data,
        isLoading: isLoading,
        error: error,
        mutate: mutate,
    };
}

export function useKeys() {
    const { data, error, isLoading, mutate } = useSWR("/authkeys", getKeys);
    return {
        keys: data,
        isLoading: isLoading,
        error: error,
        mutate: mutate,
    };
}

export function useDeployments() {
    const { data, error, isLoading, mutate } = useSWR("/deployments", getDeployments);
    return {
        deployments: data,
        isLoading: isLoading,
        error: error,
        mutate: mutate,
    };
}

export function useDeploymentLogs(uuid: string) {
    const searchParams = new URLSearchParams({ "deployment_uuid": uuid }).toString();
    const { data, error, isLoading, mutate } = useSWR(`/deploymentlogs?${searchParams}`, getDeploymentLogs);
    return {
        logs: data,
        isLoading: isLoading,
        error: error,
        mutate: mutate,
    };
}

export function useSensors(params: any = null) {
    const searchParams = new URLSearchParams(params).toString();
    const url = params ? `/sensors?${searchParams}` : "/sensors";
    const { data, error, isLoading, mutate } = useSWR(url, getSensors);
    return {
        sensors: data?.data,
        count: data?.count,
        isLoading: isLoading,
        error: error,
        mutate: mutate,
    };
}

export function useSessions(params: any = null) {
    const searchParams = new URLSearchParams(params).toString();
    const url = params ? `/api/sessions?${searchParams}` : "/api/sessions";
    const { data, error, isLoading, mutate } = useSWR(url, getSessionsClient, {
        // Prevent race conditions by not revalidating on focus during pagination
        revalidateOnFocus: false,
        revalidateOnReconnect: false,
        // Keep previous data while loading new data to prevent flickering
        keepPreviousData: true,
        // Add deduplication interval to prevent rapid requests
        dedupingInterval: 200,
        // Add error retry with backoff
        errorRetryCount: 3,
        errorRetryInterval: 1000,
        // Ensure fresh data on each request
        revalidateOnMount: true,
    });
    return {
        sessions: data?.data,
        count: data?.count,
        isLoading: isLoading,
        error: error,
        mutate: mutate,
    };
}

export function useSession(id: string | undefined) {
    const { data, error, isLoading, mutate } = useSWR(id ? `/api/sessions/${id}` : null, getSessionClient);
    if (!id) {
        return { session: null, count: null, isLoading: false, error: null, mutate: null };
    }
    return {
        session: data,
        isLoading: isLoading,
        error: error,
        mutate: mutate,
    };
}

export function useBlocklist() {
    const { data, error, isLoading, mutate } = useSWR("/blocklist", getBlocklist);
    return {
        blocklist: data,
        isLoading: isLoading,
        error: error,
        mutate: mutate,
    };
}

export function useSettings() {
    const { data, error, isLoading, mutate } = useSWR("/honeycomb", getSettings);
    return {
        settings: data,
        isLoading: isLoading,
        error: error,
        mutate: mutate,
    };
}