import { useState, useEffect } from 'react';

// Mobile: phones and tablets in portrait (390px iPhone 14, 412px Pixel, 430px Pro Max)
// Tablet: 769-1024px (tablets in landscape, small laptops)
// Desktop: > 1024px
const MOBILE_BREAKPOINT = 768;
const TABLET_BREAKPOINT = 1024;

export type ViewportSize = 'mobile' | 'tablet' | 'desktop';

export function useViewportSize(): ViewportSize {
  const [viewportSize, setViewportSize] = useState<ViewportSize>('desktop');

  useEffect(() => {
    const checkViewport = () => {
      const width = window.innerWidth;
      if (width <= MOBILE_BREAKPOINT) {
        setViewportSize('mobile');
      } else if (width <= TABLET_BREAKPOINT) {
        setViewportSize('tablet');
      } else {
        setViewportSize('desktop');
      }
    };

    // Check on mount
    checkViewport();

    // Check on resize
    window.addEventListener('resize', checkViewport);
    if (window.visualViewport) {
      window.visualViewport.addEventListener('resize', checkViewport);
    }
    window.addEventListener('orientationchange', checkViewport);

    return () => {
      window.removeEventListener('resize', checkViewport);
      if (window.visualViewport) {
        window.visualViewport.removeEventListener('resize', checkViewport);
      }
      window.removeEventListener('orientationchange', checkViewport);
    };
  }, []);

  return viewportSize;
}

export function useIsMobile(): boolean {
  const viewportSize = useViewportSize();
  return viewportSize === 'mobile';
}

export function useIsTablet(): boolean {
  const viewportSize = useViewportSize();
  return viewportSize === 'tablet';
}

export function useIsDesktop(): boolean {
  const viewportSize = useViewportSize();
  return viewportSize === 'desktop';
}
