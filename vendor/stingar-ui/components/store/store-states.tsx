import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@mui/material";
import { Badge } from "@/components/ui/badge";
import {
  Loader2,
  AlertCircle,
  RefreshCw,
  Wifi,
  WifiOff,
  Package,
  AlertTriangle
} from "lucide-react";
import { useEffect, useRef } from "react";

interface LoadingStateProps {
  message?: string;
}

export function LoadingState({ message = "Loading honeypots..." }: LoadingStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-12 space-y-4">
      <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      <p className="text-muted-foreground">{message}</p>
    </div>
  );
}

interface ErrorStateProps {
  error: Error;
  onRetry?: () => void;
  title?: string;
}

export function ErrorState({ error, onRetry, title = "Something went wrong" }: ErrorStateProps) {
  const errorMessage = error.message || "An unexpected error occurred while loading honeypots.";
  const fullErrorMessage = `${title}. ${errorMessage}`;
  const liveRegionRef = useRef<HTMLDivElement>(null);
  
  // Update live region when error appears to trigger VoiceOver announcement
  useEffect(() => {
    if (error && liveRegionRef.current) {
      // Clear and set content to force announcement
      liveRegionRef.current.textContent = '';
      // Use setTimeout to ensure the change is detected
      setTimeout(() => {
        if (liveRegionRef.current) {
          liveRegionRef.current.textContent = fullErrorMessage + (onRetry ? " Try Again button available." : "");
        }
      }, 50);
    }
  }, [error, fullErrorMessage, onRetry]);
  
  return (
    <>
      {/* Dedicated live region that's always present - updates trigger announcement */}
      <div
        ref={liveRegionRef}
        role="alert"
        aria-live="assertive"
        aria-atomic="true"
        className="sr-only"
      />
      
      <Card 
        className="border-destructive/50 bg-destructive/5"
        aria-labelledby="error-title"
        aria-describedby="error-message"
      >
        <CardContent className="flex flex-col items-center justify-center py-12 space-y-4">
          <AlertCircle className="h-12 w-12 text-destructive" aria-hidden="true" />
          <div className="text-center space-y-2">
            <h3 id="error-title" className="font-semibold text-destructive">{title}</h3>
            <p id="error-message" className="text-sm text-muted-foreground max-w-md">
              {errorMessage}
            </p>
          </div>
          {onRetry && (
            <Button 
              onClick={onRetry} 
              variant="outlined" 
              size="small" 
              startIcon={<RefreshCw className="h-4 w-4" aria-hidden="true" />} 
              className="mt-4"
            >
              Try Again
            </Button>
          )}
        </CardContent>
      </Card>
    </>
  );
}

interface EmptyStateProps {
  title?: string;
  description?: string;
  showFilters?: boolean;
  onClearFilters?: () => void;
}

export function EmptyState({
  title = "No honeypots found",
  description = "Try adjusting your search or filters to find what you're looking for.",
  showFilters = false,
  onClearFilters
}: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-12 space-y-4">
      <Package className="h-12 w-12 text-muted-foreground" />
      <div className="text-center space-y-2">
        <h3 className="font-semibold">{title}</h3>
        <p className="text-sm text-muted-foreground max-w-md">
          {description}
        </p>
      </div>
      {showFilters && onClearFilters && (
        <Button onClick={onClearFilters} variant="outlined" size="small">
          Clear Filters
        </Button>
      )}
    </div>
  );
}

interface StoreUnavailableProps {
  onRetry?: () => void;
}

export function StoreUnavailable({ onRetry }: StoreUnavailableProps) {
  const message = "HP Store Unavailable. The Honeypot Store is currently unavailable. This could be due to network issues or the store being temporarily offline. Status: Offline.";
  const liveRegionRef = useRef<HTMLDivElement>(null);
  
  // Update live region when component appears to trigger VoiceOver announcement
  useEffect(() => {
    if (liveRegionRef.current) {
      // Clear and set content to force announcement
      liveRegionRef.current.textContent = '';
      // Use setTimeout to ensure the change is detected
      setTimeout(() => {
        if (liveRegionRef.current) {
          liveRegionRef.current.textContent = message + (onRetry ? " Check Connection button available." : "");
        }
      }, 50);
    }
  }, [message, onRetry]);
  
  return (
    <>
      {/* Dedicated live region that's always present - updates trigger announcement */}
      <div
        ref={liveRegionRef}
        role="alert"
        aria-live="assertive"
        aria-atomic="true"
        className="sr-only"
      />
      
      <Card 
        className="border-orange-200 bg-orange-50"
        aria-labelledby="store-unavailable-title"
        aria-describedby="store-unavailable-message"
      >
        <CardContent className="flex flex-col items-center justify-center py-12 space-y-4">
          <div className="flex items-center space-x-2" aria-hidden="true">
            <WifiOff className="h-8 w-8 text-orange-600" />
            <AlertTriangle className="h-6 w-6 text-orange-600" />
          </div>
          <div className="text-center space-y-2">
            <h3 id="store-unavailable-title" className="font-semibold text-orange-900">HP Store Unavailable</h3>
            <p id="store-unavailable-message" className="text-sm text-orange-700 max-w-md">
              The Honeypot Store is currently unavailable. This could be due to network issues or the store being temporarily offline.
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <Badge variant="outline" className="border-orange-200 text-orange-700" aria-label="Status: Offline">
              <Wifi className="h-3 w-3 mr-1" aria-hidden="true" />
              Offline
            </Badge>
          </div>
          {onRetry && (
            <Button 
              onClick={onRetry} 
              variant="outlined" 
              size="small" 
              startIcon={<RefreshCw className="h-4 w-4" aria-hidden="true" />} 
              className="mt-4 border-orange-200 text-orange-700 hover:bg-orange-100"
            >
              Check Connection
            </Button>
          )}
        </CardContent>
      </Card>
    </>
  );
}

interface SkeletonCardProps {
  className?: string;
}

export function SkeletonCard({ className = "" }: SkeletonCardProps) {
  return (
    <Card className={`animate-pulse ${className}`}>
      <div className="p-6 space-y-4">
        <div className="flex items-start justify-between">
          <div className="space-y-2 flex-1">
            <div className="h-5 bg-muted rounded w-3/4"></div>
            <div className="h-4 bg-muted rounded w-full"></div>
            <div className="h-4 bg-muted rounded w-2/3"></div>
          </div>
          <div className="space-y-2">
            <div className="h-6 bg-muted rounded w-16"></div>
            <div className="h-6 bg-muted rounded w-20"></div>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div className="h-4 bg-muted rounded"></div>
          <div className="h-4 bg-muted rounded"></div>
          <div className="h-4 bg-muted rounded"></div>
          <div className="h-4 bg-muted rounded"></div>
        </div>
        <div className="flex space-x-2">
          <div className="h-5 bg-muted rounded w-12"></div>
          <div className="h-5 bg-muted rounded w-16"></div>
          <div className="h-5 bg-muted rounded w-14"></div>
        </div>
        <div className="h-9 bg-muted rounded"></div>
      </div>
    </Card>
  );
}

interface SkeletonGridProps {
  count?: number;
  className?: string;
}

export function SkeletonGrid({ count = 6, className = "" }: SkeletonGridProps) {
  return (
    <div className={`grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 ${className}`}>
      {Array.from({ length: count }).map((_, index) => (
        <SkeletonCard key={index} />
      ))}
    </div>
  );
}
