import {
    Card,
    CardContent,
    CardDescription,
    CardFooter,
    CardHeader,
    CardTitle,
} from "@/components/ui/card";
import { Separator } from "./ui/separator";
import { DeployDialog } from "./dialogs/deploy";
import { StoreConfig } from "@/models/configs";
import { Badge } from "./ui/badge";
import { Download, Trash2 } from "lucide-react";
import { Button } from "@mui/material";
import { useState } from "react";
import { toast } from "sonner";
import { deleteConfig } from "@/lib/actions";
import { getHoneypotDescription, getHoneypotCategory } from "@/lib/honeypot-registry";

export type StoreConfigCardProps = {
    config: StoreConfig;
    onDelete?: (configId: number) => void;
};

export function StoreConfigCard({ config, onDelete }: StoreConfigCardProps) {
    const [isDeleting, setIsDeleting] = useState(false);


    // Normalize field names if needed (handle both snake_case and camelCase)
    const configAny = config as any;
    const hpType = config.hp_type || configAny.hpType;
    const hpOptions = config.hp_options || configAny.hpOptions;

    // Update config object with normalized field names
    if (configAny.hpType && !config.hp_type) {
        (config as any).hp_type = configAny.hpType;
    }
    if (configAny.hpOptions && !config.hp_options) {
        (config as any).hp_options = configAny.hpOptions;
    }

    // Handle delete configuration - moved before conditional return
    const handleDelete = async () => {
        const displayName = config?.name?.replace(" (from store)", "") || "Unknown Configuration";

        if (!confirm(`Are you sure you want to delete "${displayName}"? This action cannot be undone.`)) {
            return;
        }

        try {
            setIsDeleting(true);
            await deleteConfig(config.id.toString());
            toast.success(`Configuration "${displayName}" deleted successfully`);

            // Trigger a refresh of the configs list
            if (onDelete) {
                onDelete(config.id);
            }
        } catch (error: any) {
            console.error("Failed to delete config:", error);
            toast.error(`Failed to delete configuration: ${error.message}`);
        } finally {
            setIsDeleting(false);
        }
    };

    // Safety check for config data
    if (!config || !hpType) {
        console.error("StoreConfigCard: Invalid config data:", config);
        return (
            <Card className="w-full min-w-0 max-w-[350px] sm:w-[350px] shadow-xl flex flex-col border-2 border-red-200 bg-gradient-to-br from-red-50 to-pink-50">
                <CardHeader className="flex-1">
                    <CardTitle className="text-lg text-red-800">Invalid Configuration</CardTitle>
                    <CardDescription className="text-red-600">
                        This configuration has invalid or missing data.
                    </CardDescription>
                </CardHeader>
                <CardFooter className="flex justify-center">
                    <Button
                        onClick={handleDelete}
                        disabled={isDeleting}
                        variant="outlined"
                        color="error"
                        size="small"
                        startIcon={<Trash2 className="w-4 h-4" />}
                    >
                        {isDeleting ? "Deleting..." : "Delete"}
                    </Button>
                </CardFooter>
            </Card>
        );
    }

    // Extract display name from config name (remove " (from store)" suffix)
    const displayName = config.name.replace(" (from store)", "");

    // Generate description based on honeypot type using dynamic system
    const getDescription = (hpType: string) => {
        return getHoneypotDescription(hpType);
    };



    return (
        <Card className="w-full min-w-0 max-w-[350px] sm:w-[350px] shadow-xl flex flex-col border-2 border-blue-200 bg-gradient-to-br from-blue-50 to-indigo-50">
            <CardHeader className="flex-1">
                <div className="flex items-center justify-between">
                    <CardTitle className="text-lg text-blue-800">{displayName}</CardTitle>
                    <Badge variant="secondary" className="bg-blue-100 text-blue-700 border-blue-300">
                        <Download className="w-3 h-3 mr-1" />
                        Store
                    </Badge>
                </div>
                <CardDescription className="text-blue-600">
                    {getDescription(config.hp_type)}
                    <br />
                    <span className="text-xs text-blue-500 italic">
                        Custom configuration with enhanced settings
                    </span>
                </CardDescription>
            </CardHeader>
            <CardContent>
                <Separator className="bg-blue-200" />
                <div className="mt-3 text-sm text-blue-700">
                    <p><strong>Type:</strong> {config.hp_type}</p>
                    <p><strong>Installed:</strong> {new Date(config.created).toLocaleDateString()}</p>
                </div>
            </CardContent>
            <CardFooter className="flex justify-between items-center">
                <Button
                    onClick={handleDelete}
                    disabled={isDeleting}
                    variant="outlined"
                    color="error"
                    size="small"
                    startIcon={<Trash2 className="w-4 h-4" />}
                >
                    {isDeleting ? "Deleting..." : "Delete"}
                </Button>
                <DeployDialog
                    type={config.hp_type}
                    title={displayName}
                    configId={config.id}
                    isStoreConfig={true}
                />
            </CardFooter>
        </Card>
    );
}
