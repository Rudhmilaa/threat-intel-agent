"use client";

import React, { useState, useCallback, useRef } from 'react';
import { useStingarEnv, EnvVariable } from '@/lib/hooks/use-stingar-env';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@mui/material';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Switch, FormControlLabel, TextField } from '@mui/material';
import { toast } from 'sonner';
import { Loader2, Save, Eye, EyeOff, Info, ChevronDown, ChevronUp } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { UpdateSettingsSection } from '@/components/update-settings';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

// Group variables by category with descriptions
// Order matches the original stingar.env file structure from configuration.md
const VARIABLE_GROUPS: Record<string, { variables: string[]; description: string; note?: string }> = {
    'Fluentd': {
        variables: [
            'FLUENTD_HOST',
            'FLUENTD_PORT',
            'FLUENTD_REMOTE_HOST',
            'FLUENTD_LOCAL_PORT',
            'FLUENTD_KEY',
            'FLUENTD_APP',
        ],
        description: 'Configuration for Fluentd logging. These values are automatically set when STINGAR is installed.',
    },
    'Fluent Bit': {
        variables: [
            'FLUENTBIT_HOST',
            'FLUENTBIT_PORT',
            'FLUENTBIT_APP',
            'FLUENTBIT_HOSTNAME',
        ],
        description: 'Configuration for Fluent Bit logging. These values are automatically set when STINGAR is installed.',
    },
    'Syslog Output': {
        variables: [
            'SYSLOG_ENABLED',
            'SYSLOG_HOST',
            'SYSLOG_PORT',
            'SYSLOG_SEVERITY',
            'SYSLOG_HOSTNAME',
            'SYSLOG_PROTOCOL',
        ],
        description: 'Configuration for syslog output of attack logs. Disabled by default, set to true to enable.',
    },
    'Local File Output': {
        variables: [
            'FILE_ENABLED',
        ],
        description: 'Configuration for local file output of attack logs. Disabled by default, set to true to enable. If enabled, the output file location is mounted/mapped to the local file system in the docker-compose.yml file.',
    },
    'CIF Configuration': {
        variables: [
            'CIF_ENABLED',
            'CIF_HOST',
            'CIF_TOKEN',
            'CIF_PROVIDER',
            'CIF_CONFIDENCE',
            'CIF_TAGS',
            'CIF_GROUP',
        ],
        description: 'Configuration for CIF (Central Intelligence Framework) to contribute your attack data anonymously to the common repository. CIF_TOKEN and CIF_PROVIDER values are provided by Forewarned, Inc. (email info@forewarned.io to request).',
        note: 'Your CIF_TOKEN & CIF_PROVIDER values will be provided by Forewarned, Inc. Email info@forewarned.io to request.',
    },
    'HP App Store Configuration': {
        variables: [
            'REMOTE_STORE_ENABLED',
            'REMOTE_STORE_API_KEY',
            'REMOTE_STORE_BASE_URL',
        ],
        description: 'Variables that control the connection to the HP App Store. When enabled, STINGAR will automatically attempt to register your instance and fetch honeypot data from the store. Authentication is handled automatically via the API key.',
        note: 'When you enable the HP App Store for the first time, STINGAR will automatically register your instance and receive an API key. This process happens in the background and does not require any user interaction. Note: Authentication-related variables (AUTH_ENABLED, AUTH_TYPE, AUTH_TOKEN) and other unused variables have been removed as they are not used by the code.',
    },
    'Local Server Settings': {
        variables: [
            'API_HOST',
            'API_KEY',
            'PASSPHRASE',
            'SALT',
            'STINGAR_SERVICE_URL',
            'UI_HOSTNAME',
        ],
        description: 'These values are set by install script and used internally by STINGAR, typically not modified.',
    },
    'Honeypot Configuration': {
        variables: [
            'HONEYPOT_HEALTHCHECK_INTERVAL',
            'TAGS',
        ],
        description: 'Configuration for honeypot health checks and tagging.',
    },
    'LDAP Configuration': {
        variables: [
            'LDAP_ENABLED',
            'LDAP_HOST',
            'LDAP_PORT',
            'LDAP_BASE',
        ],
        description: 'Enable LDAP to use your organization\'s institutional identity management system to authenticate STINGAR users. Users will still need to be added to STINGAR via the User Management module.',
    },
    'UI Settings': {
        variables: [
            'INSTITUTION_NAME',
            'CONTACT_EMAIL',
            'THEME_DARK_BASE_COLOR',
            'THEME_LIGHT_BASE_COLOR',
            'DEFAULT_ROWS_PER_PAGE',
            'SESSIONS_DEFAULT_DATE_RANGE',
        ],
        description: 'Miscellaneous UI settings including institution name, contact email, theme colors, default pagination, and Attack Analysis date range.',
    },
    'Docker Repository (Deprecated)': {
        variables: [
            'DOCKER_USERNAME',
            'DOCKER_REPOSITORY',
            'DOCKER_PASSWORD',
        ],
        description: 'Docker code repository settings. These are deprecated and automatically set when STINGAR is installed. Should not be modified.',
    },
    'Other Configuration': {
        variables: [],
        description: 'Additional environment variables that are not explicitly categorized. These may be custom variables or variables added in future versions of STINGAR.',
    },
};

function VariableField({ variable, value, onChange, onBlur }: {
    variable: EnvVariable;
    value: string;
    onChange: (value: string) => void;
    onBlur?: () => void;
}) {
    const [showValue, setShowValue] = useState(!variable.sensitive);
    // Use raw_value if available (for sensitive fields), otherwise use value
    const actualValue = variable.raw_value !== null && variable.raw_value !== undefined
        ? variable.raw_value
        : value;
    const [localValue, setLocalValue] = useState(actualValue);

    // Update local value if external value changes (e.g., after save/reset)
    React.useEffect(() => {
        // Always use raw_value when available to ensure we have the full value
        const newValue = variable.raw_value !== null && variable.raw_value !== undefined
            ? variable.raw_value
            : value;
        setLocalValue(newValue);
    }, [value, variable.raw_value]);

    const handleChange = (newValue: string) => {
        setLocalValue(newValue);
        onChange(newValue);
    };

    if (variable.type === 'boolean') {
        const boolValue = localValue.toLowerCase() === 'true' || localValue === '1' || localValue === 'yes';
        return (
            <div className="space-y-2">
                <div className="flex items-center justify-between">
                    <div className="flex-1">
                        <Label htmlFor={variable.name} className="text-sm font-semibold">
                            {variable.display_name}
                        </Label>
                        <code className="text-xs text-muted-foreground ml-2">{variable.name}</code>
                    </div>
                    <Switch
                        checked={boolValue}
                        onChange={(e) => {
                            const newValue = e.target.checked ? 'true' : 'false';
                            handleChange(newValue);
                        }}
                    />
                </div>
                {variable.description && (
                    <p className="text-sm text-muted-foreground">{variable.description}</p>
                )}
            </div>
        );
    }

    return (
        <div className="space-y-2">
            <div className="flex items-center justify-between">
                <div className="flex-1">
                    <Label htmlFor={variable.name} className="text-sm font-semibold">
                        {variable.display_name}
                    </Label>
                    <code className="text-xs text-muted-foreground ml-2">{variable.name}</code>
                </div>
                {variable.sensitive && (
                    <Button
                        type="button"
                        variant="text"
                        size="small"
                        onClick={() => setShowValue(!showValue)}
                        sx={{ minWidth: 'auto', padding: '4px' }}
                        startIcon={showValue ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    >
                        {showValue ? 'Hide' : 'Show'}
                    </Button>
                )}
            </div>
            {variable.description && (
                <p className="text-sm text-muted-foreground">{variable.description}</p>
            )}
            <Input
                id={variable.name}
                type={variable.sensitive && !showValue ? 'password' : variable.type === 'email' ? 'email' : variable.type === 'url' ? 'url' : variable.type === 'number' ? 'number' : 'text'}
                value={localValue}
                onChange={(e) => handleChange(e.target.value)}
                onBlur={onBlur}
                placeholder={variable.default || ''}
                className={variable.sensitive ? 'font-mono' : ''}
            />
            {variable.default && localValue === '' && (
                <p className="text-xs text-muted-foreground">Default: {variable.default}</p>
            )}
        </div>
    );
}

export default function SettingsPage() {
    const { variables, isLoading, error, refetch, updateVariables } = useStingarEnv();
    const [editedValues, setEditedValues] = useState<Record<string, string>>({});
    const [isSaving, setIsSaving] = useState(false);
    const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false);
    const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>({});
    const hasInitializedRef = useRef(false);
    const [activeTab, setActiveTab] = useState<string>('env');

    // Check URL params for tab
    React.useEffect(() => {
        if (typeof window !== 'undefined') {
            const params = new URLSearchParams(window.location.search);
            const tab = params.get('tab');
            if (tab === 'updates') {
                setActiveTab('updates');
            }
        }
    }, []);

    // Initialize edited values from variables (only once)
    React.useEffect(() => {
        if (!hasInitializedRef.current && variables.length > 0) {
            const initialValues: Record<string, string> = {};
            variables.forEach(v => {
                initialValues[v.name] = v.raw_value ?? v.value;
            });
            setEditedValues(initialValues);
            hasInitializedRef.current = true;
        }
    }, [variables]);

    // Track if there are unsaved changes
    React.useEffect(() => {
        if (variables.length === 0) return;

        const hasChanges = Object.keys(editedValues).some(key => {
            const variable = variables.find(v => v.name === key);
            if (!variable) return false;
            // Always use raw_value when available to compare with full value
            const currentValue = (variable.raw_value !== null && variable.raw_value !== undefined)
                ? variable.raw_value
                : variable.value;
            return editedValues[key] !== currentValue;
        });
        setHasUnsavedChanges(hasChanges);
    }, [editedValues, variables]);

    const handleVariableChange = useCallback((variableName: string, value: string) => {
        setEditedValues(prev => ({
            ...prev,
            [variableName]: value,
        }));
    }, []);

    const handleSave = useCallback(async () => {
        if (!hasUnsavedChanges) {
            toast.info('No changes to save');
            return;
        }

        setIsSaving(true);
        try {
            // Prepare updates (only changed values)
            const updates: Record<string, string> = {};
            variables.forEach(v => {
                // Always use raw_value when available to compare with full value
                const currentValue = (v.raw_value !== null && v.raw_value !== undefined)
                    ? v.raw_value
                    : v.value;
                const editedValue = editedValues[v.name];
                if (editedValue !== undefined && editedValue !== currentValue) {
                    updates[v.name] = editedValue;
                }
            });

            if (Object.keys(updates).length === 0) {
                toast.info('No changes to save');
                setIsSaving(false);
                return;
            }

            const result = await updateVariables(updates);

            toast.success(`Successfully updated ${result.data.updated} variable(s)`);

            // Show action results
            result.data.actions.forEach(action => {
                if (action.status === 'success') {
                    toast.success(`${action.variable}: ${action.message}`);
                } else if (action.status === 'warning') {
                    toast.warning(`${action.variable}: ${action.message}`);
                } else if (action.status === 'error') {
                    toast.error(`${action.variable}: ${action.message}`);
                }
            });

            // Reset edited values
            const newValues: Record<string, string> = {};
            variables.forEach(v => {
                // Always use raw_value when available to ensure we have the full value
                newValues[v.name] = (v.raw_value !== null && v.raw_value !== undefined)
                    ? v.raw_value
                    : v.value;
            });
            setEditedValues(newValues);
            setHasUnsavedChanges(false);

            // Refetch to get updated values
            await refetch();
        } catch (err: any) {
            console.error('Failed to save settings:', err);
            const errorMessage = err.details || err.message || 'Failed to save settings';
            toast.error(errorMessage);
        } finally {
            setIsSaving(false);
        }
    }, [editedValues, variables, hasUnsavedChanges, updateVariables, refetch]);

    const handleReset = useCallback(() => {
        const resetValues: Record<string, string> = {};
        variables.forEach(v => {
            // Always use raw_value when available to ensure we have the full value
            resetValues[v.name] = (v.raw_value !== null && v.raw_value !== undefined)
                ? v.raw_value
                : v.value;
        });
        setEditedValues(resetValues);
        setHasUnsavedChanges(false);
        toast.info('Changes reset');
    }, [variables]);

    const toggleGroup = useCallback((groupName: string) => {
        setExpandedGroups(prev => ({
            ...prev,
            [groupName]: !prev[groupName]
        }));
    }, []);

    // Group variables - use group from API if available, otherwise use VARIABLE_GROUPS
    const groupedVariables: Record<string, { variables: EnvVariable[]; description: string; note?: string }> = {};

    // First, group by API group field if available
    const variablesByGroup: Record<string, EnvVariable[]> = {};
    variables.forEach(v => {
        const group = v.group || 'Other Configuration';
        if (!variablesByGroup[group]) {
            variablesByGroup[group] = [];
        }
        variablesByGroup[group].push(v);
    });

    // Build grouped variables maintaining order from VARIABLE_GROUPS
    Object.entries(VARIABLE_GROUPS).forEach(([groupName, groupConfig]) => {
        const groupVars = variablesByGroup[groupName] || [];
        if (groupVars.length > 0) {
            groupedVariables[groupName] = {
                variables: groupVars,
                description: groupConfig.description,
                note: groupConfig.note,
            };
        }
    });

    // Add any groups from API that aren't in VARIABLE_GROUPS
    Object.entries(variablesByGroup).forEach(([groupName, groupVars]) => {
        if (!groupedVariables[groupName] && groupVars.length > 0) {
            groupedVariables[groupName] = {
                variables: groupVars,
                description: 'Additional system configuration variables.',
            };
        }
    });

    if (isLoading) {
        return (
            <div className="flex items-center justify-center h-64">
                <Loader2 className="h-8 w-8 animate-spin" />
                <span className="ml-2">Loading settings...</span>
            </div>
        );
    }

    if (error) {
        return (
            <div className="flex flex-col items-center justify-center h-64">
                <p className="text-red-500 mb-4">Failed to load settings: {error.message}</p>
                <Button onClick={() => refetch()}>Retry</Button>
            </div>
        );
    }

    return (
        <div className="flex flex-col max-h-full w-full">
            <div className="flex items-center justify-between pb-4">
                <div>
                    <h1 className="text-xl font-bold">Settings</h1>
                    <p className="text-sm text-muted-foreground mt-1">
                        Manage environment variables and system updates for this STINGAR instance
                    </p>
                </div>
                <div className="flex gap-2">
                    {hasUnsavedChanges && (
                        <Button variant="outlined" onClick={handleReset} disabled={isSaving}>
                            Reset
                        </Button>
                    )}
                    <Button
                        variant="contained"
                        onClick={handleSave}
                        disabled={!hasUnsavedChanges || isSaving}
                        startIcon={isSaving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                    >
                        {isSaving ? 'Saving...' : 'Save Changes'}
                    </Button>
                </div>
            </div>

            <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
                <TabsList className="mb-4">
                    <TabsTrigger value="env">Environment Variables</TabsTrigger>
                    <TabsTrigger value="updates">System Updates</TabsTrigger>
                </TabsList>

                <TabsContent value="env" className="space-y-6">
                    {Object.entries(groupedVariables).map(([groupName, groupConfig]) => {
                    const isExpanded = expandedGroups[groupName] ?? false;
                    return (
                        <Card key={groupName}>
                            <CardHeader
                                className="cursor-pointer hover:bg-muted/50 transition-colors"
                                onClick={() => toggleGroup(groupName)}
                            >
                                <div className="flex items-center justify-between">
                                    <div className="flex-1">
                                        <CardTitle className="flex items-center gap-2">
                                            {groupName}
                                            <span className="text-sm font-normal text-muted-foreground">
                                                ({groupConfig.variables.length} variable{groupConfig.variables.length !== 1 ? 's' : ''})
                                            </span>
                                        </CardTitle>
                                        <CardDescription className="mt-2">
                                            {groupConfig.description}
                                        </CardDescription>
                                    </div>
                                    <div className="ml-4">
                                        {isExpanded ? (
                                            <ChevronUp className="h-5 w-5 text-muted-foreground" />
                                        ) : (
                                            <ChevronDown className="h-5 w-5 text-muted-foreground" />
                                        )}
                                    </div>
                                </div>
                            </CardHeader>
                            {isExpanded && (
                                <CardContent className="space-y-6">
                                    {groupConfig.note && (
                                        <Alert className="border-blue-200 bg-blue-50 dark:bg-blue-950 dark:border-blue-800">
                                            <Info className="h-4 w-4 text-blue-600 dark:text-blue-400" />
                                            <AlertTitle className="text-blue-800 dark:text-blue-300">Note</AlertTitle>
                                            <AlertDescription className="text-blue-700 dark:text-blue-200">
                                                {groupConfig.note}
                                            </AlertDescription>
                                        </Alert>
                                    )}
                                    {groupConfig.variables.map((variable) => {
                                        // Always use raw_value when available to compare with full value
                                        const currentValue = (variable.raw_value !== null && variable.raw_value !== undefined)
                                            ? variable.raw_value
                                            : variable.value;
                                        const editedValue = editedValues[variable.name] ?? currentValue;
                                        const isChanged = editedValue !== currentValue;

                                        return (
                                            <div
                                                key={variable.name}
                                                className={`p-4 rounded-lg border ${isChanged ? 'border-blue-500 bg-blue-50 dark:bg-blue-950' : 'border-border'}`}
                                            >
                                                <VariableField
                                                    variable={variable}
                                                    value={editedValue}
                                                    onChange={(value) => handleVariableChange(variable.name, value)}
                                                />
                                                {isChanged && (
                                                    <p className="text-xs text-blue-600 dark:text-blue-400 mt-2">
                                                        Changed from: {currentValue || '(empty)'}
                                                    </p>
                                                )}
                                            </div>
                                        );
                                    })}
                                </CardContent>
                            )}
                        </Card>
                    );
                })}

                {variables.length === 0 && (
                        <Card>
                            <CardContent className="py-8 text-center text-muted-foreground">
                                No environment variables found
                            </CardContent>
                        </Card>
                    )}
                </TabsContent>

                <TabsContent value="updates">
                    <UpdateSettingsSection />
                </TabsContent>
            </Tabs>
        </div>
    );
}

