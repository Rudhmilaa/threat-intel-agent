import { useEffect } from 'react';

/**
 * Hook to set the page title for client components
 * @param title - The page title (will be appended with " | STINGAR")
 */
export function usePageTitle(title: string) {
  useEffect(() => {
    const fullTitle = title ? `${title} | STINGAR` : 'STINGAR';
    document.title = fullTitle;
    
    // Cleanup: restore default title when component unmounts
    return () => {
      document.title = 'STINGAR';
    };
  }, [title]);
}
