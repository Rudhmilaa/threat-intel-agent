"use client"

import React from 'react';
import { SeverityIndicator, SeverityLevel } from '@/lib/severity';
import { Badge } from '@/components/ui/badge';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';

interface SeverityIndicatorProps {
  indicator: SeverityIndicator;
  compact?: boolean;
}

/**
 * Unified Severity Indicator Component
 * 
 * Provides consistent visual representation across all honeypot types:
 * - Uses ASCII block characters with height-based severity representation
 * - Uses consistent color scheme based on severity level
 * - Properly aligned vertically for table display
 * - Tooltips provide detailed information
 */

// Unicode block characters for severity levels (increasing height)
const SEVERITY_BLOCKS: Record<SeverityLevel, string> = {
  [SeverityLevel.LOW]: "\u2581",      // ▁ Lower one eighth block
  [SeverityLevel.MEDIUM]: "\u2584",    // ▄ Lower half block
  [SeverityLevel.HIGH]: "\u2586",      // ▆ Lower three quarters block
  [SeverityLevel.CRITICAL]: "\u2587",  // ▇ Full block
  [SeverityLevel.EXTREME]: "\u2588"    // █ Full block (solid)
};

export function SeverityIndicatorComponent({ 
  indicator, 
  compact = false
}: SeverityIndicatorProps) {
  if (compact) {
    const blockChar = SEVERITY_BLOCKS[indicator.level] || SEVERITY_BLOCKS[SeverityLevel.LOW];
    
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            <div
              className="flex items-center justify-center cursor-pointer"
              style={{ 
                width: '20px', 
                height: '20px',
                minWidth: '20px',
                minHeight: '20px',
                fontFamily: 'monospace',
                fontSize: '16px',
                lineHeight: '20px'
              }}
              aria-label={indicator.label}
            >
              <span style={{ color: indicator.color }}>
                {blockChar}
              </span>
            </div>
          </TooltipTrigger>
          <TooltipContent>
            <div className="space-y-1">
              <div className="font-semibold">{indicator.label}</div>
              <div className="text-sm text-muted-foreground">{indicator.description}</div>
              <div className="text-xs text-muted-foreground">Score: {indicator.score.toFixed(2)}</div>
            </div>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  }

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge
            variant="outline"
            className="cursor-pointer"
            style={{
              borderColor: indicator.color,
              color: indicator.color,
              backgroundColor: `${indicator.color}15`
            }}
          >
            {indicator.label}
          </Badge>
        </TooltipTrigger>
        <TooltipContent>
          <div className="space-y-1">
            <div className="font-semibold">{indicator.label}</div>
            <div className="text-sm text-muted-foreground">{indicator.description}</div>
            <div className="text-xs text-muted-foreground">Score: {indicator.score.toFixed(2)}</div>
          </div>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

