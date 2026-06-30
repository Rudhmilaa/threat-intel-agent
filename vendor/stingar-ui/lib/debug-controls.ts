/**
 * Debug Controls for Stingar UI
 * 
 * This module provides easy ways to control debug logging in the browser.
 * It can be used in the browser console or imported by other modules.
 */

import { setDebugMode, isDebug, debugLog } from './debug';

/**
 * Debug control interface for browser console
 */
export interface DebugControls {
  enable: () => void;
  disable: () => void;
  toggle: () => void;
  status: () => void;
  test: () => void;
}

/**
 * Create debug controls object
 */
export function createDebugControls(): DebugControls {
  return {
    enable: () => {
      setDebugMode(true);
      console.log('🔧 Debug mode ENABLED - Verbose logging is now active');
      console.log('You can now see detailed debug information in the console');
    },
    
    disable: () => {
      setDebugMode(false);
      console.log('🔧 Debug mode DISABLED - Verbose logging is now inactive');
      console.log('Only errors and warnings will be shown');
    },
    
    toggle: () => {
      const currentStatus = isDebug();
      setDebugMode(!currentStatus);
      console.log(`🔧 Debug mode ${!currentStatus ? 'ENABLED' : 'DISABLED'}`);
    },
    
    status: () => {
      const status = isDebug();
      console.log(`🔧 Debug mode is currently: ${status ? 'ENABLED' : 'DISABLED'}`);
      if (status) {
        console.log('Verbose logging is active - you should see detailed debug information');
      } else {
        console.log('Only errors and warnings are shown - use stingarDebug.enable() to see more');
      }
    },
    
    test: () => {
      console.log('🧪 Testing debug logging...');
      debugLog('This is a test debug message - you should only see this if debug mode is enabled');
      console.log('If you see the debug message above, debug mode is working correctly');
    }
  };
}

/**
 * Initialize debug controls in the browser
 */
export function initializeDebugControls(): void {
  if (typeof window !== 'undefined') {
    const controls = createDebugControls();
    (window as any).stingarDebug = controls;
    
    // Show initial status
    console.log('🔧 Stingar Debug Controls initialized');
    console.log('Available commands:');
    console.log('  stingarDebug.enable()  - Enable verbose debug logging');
    console.log('  stingarDebug.disable() - Disable verbose debug logging');
    console.log('  stingarDebug.toggle()  - Toggle debug mode on/off');
    console.log('  stingarDebug.status()  - Show current debug status');
    console.log('  stingarDebug.test()    - Test debug logging');
    
    controls.status();
  }
}

/**
 * Auto-initialize debug controls in development
 */
if (typeof window !== 'undefined' && process.env.NODE_ENV === 'development') {
  // Initialize immediately in development
  initializeDebugControls();
  
  // Also initialize when the page loads
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeDebugControls);
  }
}

// Export the controls for manual initialization
export const debugControls = createDebugControls();
