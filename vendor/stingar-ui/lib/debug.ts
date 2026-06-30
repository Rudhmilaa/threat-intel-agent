/**
 * Debug utility for conditional logging
 * 
 * This utility provides a centralized way to control debug output
 * based on environment variables and debug mode settings.
 */

// Check if we're in debug mode
const isDebugMode = (): boolean => {
  // Check for explicit debug environment variable
  if (typeof window !== 'undefined') {
    // Client-side: check localStorage or URL params
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('debug') === 'true') {
      return true;
    }
    if (localStorage.getItem('stingar-debug') === 'true') {
      return true;
    }
  }

  // Check environment variables (works on both client and server)
  // Note: We don't automatically enable debug mode in development
  // Users must explicitly enable it via URL parameter, localStorage, or environment variable

  if (process.env.NEXT_PUBLIC_DEBUG === 'true') {
    return true;
  }

  if (process.env.STINGAR_DEBUG === 'true') {
    return true;
  }

  return false;
};

// Debug logger class
class DebugLogger {
  private enabled: boolean;

  constructor() {
    this.enabled = isDebugMode();
  }

  // Enable/disable debug mode programmatically
  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
    if (typeof window !== 'undefined') {
      if (enabled) {
        localStorage.setItem('stingar-debug', 'true');
      } else {
        localStorage.removeItem('stingar-debug');
      }
    }
  }

  // Check if debug is enabled
  isEnabled(): boolean {
    return this.enabled;
  }

  // Debug log (only shows in debug mode)
  log(...args: any[]): void {
    if (this.enabled) {
      console.log('[DEBUG]', ...args);
    }
  }

  // Debug info (only shows in debug mode)
  info(...args: any[]): void {
    if (this.enabled) {
      console.info('[DEBUG]', ...args);
    }
  }

  // Debug warn (only shows in debug mode)
  warn(...args: any[]): void {
    if (this.enabled) {
      console.warn('[DEBUG]', ...args);
    }
  }

  // Debug error (always shows, but with debug prefix in debug mode)
  error(...args: any[]): void {
    if (this.enabled) {
      console.error('[DEBUG]', ...args);
    } else {
      console.error(...args);
    }
  }

  // Debug group (only shows in debug mode)
  group(label: string): void {
    if (this.enabled) {
      console.group(`[DEBUG] ${label}`);
    }
  }

  // Debug group end (only shows in debug mode)
  groupEnd(): void {
    if (this.enabled) {
      console.groupEnd();
    }
  }

  // Debug table (only shows in debug mode)
  table(data: any): void {
    if (this.enabled) {
      console.table(data);
    }
  }

  // Debug time (only shows in debug mode)
  time(label: string): void {
    if (this.enabled) {
      console.time(`[DEBUG] ${label}`);
    }
  }

  // Debug time end (only shows in debug mode)
  timeEnd(label: string): void {
    if (this.enabled) {
      console.timeEnd(`[DEBUG] ${label}`);
    }
  }

  // Conditional execution (only runs in debug mode)
  ifEnabled<T>(fn: () => T): T | undefined {
    if (this.enabled) {
      return fn();
    }
    return undefined;
  }
}

// Create singleton instance
const debugLogger = new DebugLogger();

// Export the logger and utility functions
export const debug = debugLogger;

// Export utility functions for convenience
export const isDebug = (): boolean => debugLogger.isEnabled();
export const setDebugMode = (enabled: boolean): void => debugLogger.setEnabled(enabled);

// Export conditional logging functions
export const debugLog = (...args: any[]) => debugLogger.log(...args);
export const debugInfo = (...args: any[]) => debugLogger.info(...args);
export const debugWarn = (...args: any[]) => debugLogger.warn(...args);
export const debugError = (...args: any[]) => debugLogger.error(...args);
export const debugGroup = (label: string) => debugLogger.group(label);
export const debugGroupEnd = () => debugLogger.groupEnd();
export const debugTable = (data: any) => debugLogger.table(data);
export const debugTime = (label: string) => debugLogger.time(label);
export const debugTimeEnd = (label: string) => debugLogger.timeEnd(label);

// Export conditional execution
export const debugIf = <T>(fn: () => T): T | undefined => debugLogger.ifEnabled(fn);

// Development helper: add debug controls to window object in development
if (typeof window !== 'undefined' && process.env.NODE_ENV === 'development') {
  (window as any).stingarDebug = {
    enable: () => setDebugMode(true),
    disable: () => setDebugMode(false),
    isEnabled: isDebug,
    log: debugLog,
    info: debugInfo,
    warn: debugWarn,
    error: debugError,
    group: debugGroup,
    groupEnd: debugGroupEnd,
    table: debugTable,
    time: debugTime,
    timeEnd: debugTimeEnd,
  };
}
