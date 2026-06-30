import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@mui/material";
import { Badge } from "@/components/ui/badge";
import { Download, Star, Eye, Clock, Tag as TagIcon, Database, Wifi, AlertTriangle } from "lucide-react";
import { HoneypotStore } from "@/models/store";
import { useInstallHoneypot } from "@/lib/hooks/use-store";
import { toast } from "sonner";
import { InstallationSuccessDialog } from "./installation-success-dialog";

interface HoneypotCardProps {
  honeypot: HoneypotStore;
  onInstall?: (honeypot: HoneypotStore) => void;
  showInstallButton?: boolean;
}

export function HoneypotCard({
  honeypot,
  onInstall,
  showInstallButton = true
}: HoneypotCardProps) {
  const [isInstalling, setIsInstalling] = useState(false);
  const [showSuccessDialog, setShowSuccessDialog] = useState(false);
  const { installHoneypot } = useInstallHoneypot();

  const handleInstall = async () => {
    if (isInstalling) return;

    setIsInstalling(true);
    try {
      await installHoneypot(honeypot.id, {
        // autoDeploy: true, // TODO: Re-enable auto-deployment feature in future
        configuration: honeypot.configuration,
      });

      // Show success dialog instead of toast
      setShowSuccessDialog(true);
      onInstall?.(honeypot);
    } catch (error) {
      console.error('Installation failed:', error);
      toast.error(`Failed to install ${honeypot.name}: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setIsInstalling(false);
    }
  };

  const getStatusBadge = () => {
    if (honeypot.installationStatus) {
      switch (honeypot.installationStatus.status) {
        case 'installed':
          return <Badge variant="default" className="bg-green-100 text-green-800">Installed</Badge>;
        case 'installing':
          return <Badge variant="default" className="bg-blue-100 text-blue-800">Installing</Badge>;
        case 'failed':
          return <Badge variant="destructive">Failed</Badge>;
        case 'updating':
          return <Badge variant="default" className="bg-yellow-100 text-yellow-800">Updating</Badge>;
        default:
          return null;
      }
    }
    return null;
  };

  const getCategoryBadge = () => {
    const categoryColors: Record<string, string> = {
      'Network': 'bg-blue-100 text-blue-800',
      'Web': 'bg-purple-100 text-purple-800',
      'ICS': 'bg-orange-100 text-orange-800',
      'IoT': 'bg-green-100 text-green-800',
      'Database': 'bg-red-100 text-red-800',
    };

    const colorClass = categoryColors[honeypot.category] || 'bg-gray-100 text-gray-800';
    return <Badge variant="outline" className={colorClass}>{honeypot.category}</Badge>;
  };

  const getDataSourceBadge = () => {
    if (!honeypot.dataSource) return null;

    if (honeypot.dataSource === 'remote') {
      return (
        <Badge variant="outline" className="bg-green-100 text-green-800 border-green-300">
          <Wifi className="h-3 w-3 mr-1" />
          Live
        </Badge>
      );
    } else if (honeypot.dataSource === 'cache') {
      return (
        <Badge variant="outline" className="bg-yellow-100 text-yellow-800 border-yellow-300">
          <Database className="h-3 w-3 mr-1" />
          Cached
        </Badge>
      );
    }
    return null;
  };

  const getStalenessIndicator = () => {
    if (honeypot.dataSource === 'cache' && honeypot.isStale) {
      return (
        <div className="flex items-center space-x-1 text-xs text-yellow-600">
          <AlertTriangle className="h-3 w-3" />
          <span>Stale data</span>
        </div>
      );
    }
    return null;
  };

  return (
    <Card className="hover:shadow-lg transition-shadow duration-200">
      <CardHeader>
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <CardTitle className="text-lg font-semibold mb-2">
              {honeypot.name}
            </CardTitle>
            <CardDescription className="text-sm text-muted-foreground mb-3" style={{ whiteSpace: 'pre-line' }}>
              {honeypot.description}
            </CardDescription>
          </div>
          <div className="flex flex-col items-end space-y-2">
            {getStatusBadge()}
            {getCategoryBadge()}
            {getDataSourceBadge()}
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Metadata */}
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div className="flex items-center space-x-2">
            <TagIcon className="h-4 w-4 text-muted-foreground" />
            <span className="font-medium">{honeypot.hpType}</span>
          </div>
          <div className="flex items-center space-x-2">
            <Eye className="h-4 w-4 text-muted-foreground" />
            <span className="font-medium">{honeypot.downloads.toLocaleString()}</span>
          </div>
          <div className="flex items-center space-x-2">
            <Star className="h-4 w-4 text-muted-foreground" />
            <span className="font-medium">{honeypot.rating.toFixed(1)}</span>
          </div>
          <div className="flex items-center space-x-2">
            <Clock className="h-4 w-4 text-muted-foreground" />
            <span className="font-medium">v{honeypot.version}</span>
          </div>
        </div>

        {/* Tags */}
        {honeypot.tags && honeypot.tags.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {honeypot.tags.slice(0, 3).map((tag, index) => (
              <Badge key={index} variant="secondary" className="text-xs">
                {tag}
              </Badge>
            ))}
            {honeypot.tags.length > 3 && (
              <Badge variant="secondary" className="text-xs">
                +{honeypot.tags.length - 3} more
              </Badge>
            )}
          </div>
        )}

        {/* Author and Data Source Info */}
        <div className="flex items-center justify-between">
          <div className="text-xs text-muted-foreground">
            by {honeypot.author}
          </div>
          {getStalenessIndicator()}
        </div>

        {/* Install Button */}
        {showInstallButton && (
          <Button
            onClick={handleInstall}
            disabled={isInstalling || honeypot.installationStatus?.status === 'installing'}
            variant={honeypot.installationStatus?.status === 'installed' ? 'outlined' : 'contained'}
            color={honeypot.installationStatus?.status === 'installed' ? 'success' : 'primary'}
            size="small"
            startIcon={<Download className="h-4 w-4" />}
            fullWidth
          >
            {isInstalling ? 'Installing...' :
              honeypot.installationStatus?.status === 'installed' ? 'Installed' :
                'Install Configuration'}
          </Button>
        )}
      </CardContent>
      <InstallationSuccessDialog
        open={showSuccessDialog}
        onClose={() => setShowSuccessDialog(false)}
        honeypotName={honeypot.name}
      />
    </Card>
  );
}
