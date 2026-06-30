import { useState, useEffect } from 'react';

/**
 * Hook to detect browser zoom level
 * Returns true if zoom is >= 125% (for shorter headers and reduced spacing)
 * Uses multiple detection methods for better reliability
 */
export function useHighZoom(): boolean {
  const [isHighZoom, setIsHighZoom] = useState(false);

  useEffect(() => {
    const checkZoom = () => {
      let zoomLevel = 1;
      
      // Method 1: Use visual viewport if available (most accurate for browser zoom)
      if (window.visualViewport && window.visualViewport.width > 0) {
        // visualViewport.width gives CSS pixels, window.innerWidth gives layout pixels
        // At 200% zoom: visualViewport.width = window.innerWidth / 2
        const vpWidth = window.visualViewport.width;
        const innerWidth = window.innerWidth;
        if (vpWidth > 0 && innerWidth > 0) {
          zoomLevel = innerWidth / vpWidth;
        }
      }
      
      // Method 2: Use test element (fallback if visualViewport not available)
      if (zoomLevel === 1 || zoomLevel < 1.1) {
        try {
          const testElement = document.createElement('div');
          testElement.style.cssText = 'width:100px;position:absolute;left:-9999px;visibility:hidden';
          document.body.appendChild(testElement);
          const testWidth = testElement.offsetWidth;
          document.body.removeChild(testElement);
          if (testWidth > 0) {
            zoomLevel = testWidth / 100;
          }
        } catch (e) {
          // Fallback failed, use default
        }
      }
      
      // Method 3: Compare screen to window (last resort)
      if (zoomLevel === 1 || zoomLevel < 1.1) {
        if (screen.availWidth && window.innerWidth && window.innerWidth > 0) {
          const ratio = screen.availWidth / window.innerWidth;
          // Only use this if ratio is significantly different from 1
          if (ratio > 1.2 || ratio < 0.8) {
            zoomLevel = ratio;
          }
        }
      }
      
      // If zoom is >= 1.25 (125%), consider it high zoom
      setIsHighZoom(zoomLevel >= 1.25);
    };

    // Check on mount with a small delay to ensure DOM is ready
    const timeoutId = setTimeout(checkZoom, 100);

    // Check on resize and zoom changes
    window.addEventListener('resize', checkZoom);
    if (window.visualViewport) {
      window.visualViewport.addEventListener('resize', checkZoom);
      window.visualViewport.addEventListener('scroll', checkZoom);
    }
    window.addEventListener('orientationchange', checkZoom);
    
    return () => {
      clearTimeout(timeoutId);
      window.removeEventListener('resize', checkZoom);
      if (window.visualViewport) {
        window.visualViewport.removeEventListener('resize', checkZoom);
        window.visualViewport.removeEventListener('scroll', checkZoom);
      }
      window.removeEventListener('orientationchange', checkZoom);
    };
  }, []);

  return isHighZoom;
}

/**
 * Hook to detect if zoom is at 150% or higher
 * At 150% zoom, should reduce to minimal columns
 * Uses multiple detection methods for better reliability
 */
export function useVeryHighZoom(): boolean {
  const [isVeryHighZoom, setIsVeryHighZoom] = useState(false);

  useEffect(() => {
    const checkZoom = () => {
      let zoomLevel = 1;
      
      // Method 1: Use visual viewport if available (most accurate for browser zoom)
      if (window.visualViewport && window.visualViewport.width > 0) {
        // visualViewport.width gives CSS pixels, window.innerWidth gives layout pixels
        // At 200% zoom: visualViewport.width = window.innerWidth / 2
        const vpWidth = window.visualViewport.width;
        const innerWidth = window.innerWidth;
        if (vpWidth > 0 && innerWidth > 0) {
          zoomLevel = innerWidth / vpWidth;
        }
      }
      
      // Method 2: Use test element (fallback if visualViewport not available)
      if (zoomLevel === 1 || zoomLevel < 1.1) {
        try {
          const testElement = document.createElement('div');
          testElement.style.cssText = 'width:100px;position:absolute;left:-9999px;visibility:hidden';
          document.body.appendChild(testElement);
          const testWidth = testElement.offsetWidth;
          document.body.removeChild(testElement);
          if (testWidth > 0) {
            zoomLevel = testWidth / 100;
          }
        } catch (e) {
          // Fallback failed, use default
        }
      }
      
      // Method 3: Compare screen to window (last resort)
      if (zoomLevel === 1 || zoomLevel < 1.1) {
        if (screen.availWidth && window.innerWidth && window.innerWidth > 0) {
          const ratio = screen.availWidth / window.innerWidth;
          // Only use this if ratio is significantly different from 1
          if (ratio > 1.5 || ratio < 0.7) {
            zoomLevel = ratio;
          }
        }
      }
      
      // If zoom is >= 1.5 (150%), consider it very high zoom
      setIsVeryHighZoom(zoomLevel >= 1.5);
    };

    // Check on mount with a small delay to ensure DOM is ready
    const timeoutId = setTimeout(checkZoom, 100);

    // Check on resize and zoom changes
    window.addEventListener('resize', checkZoom);
    if (window.visualViewport) {
      window.visualViewport.addEventListener('resize', checkZoom);
      window.visualViewport.addEventListener('scroll', checkZoom);
    }
    window.addEventListener('orientationchange', checkZoom);
    
    return () => {
      clearTimeout(timeoutId);
      window.removeEventListener('resize', checkZoom);
      if (window.visualViewport) {
        window.visualViewport.removeEventListener('resize', checkZoom);
        window.visualViewport.removeEventListener('scroll', checkZoom);
      }
      window.removeEventListener('orientationchange', checkZoom);
    };
  }, []);

  return isVeryHighZoom;
}
