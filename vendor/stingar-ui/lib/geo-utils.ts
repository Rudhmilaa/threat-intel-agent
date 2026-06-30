/**
 * Geo-related utility functions for displaying location data
 */

/**
 * Convert a 2-letter country code to a flag emoji
 * @param countryCode - 2-letter ISO country code (e.g., "US", "CA", "KR")
 * @returns Flag emoji string or default flag if invalid
 * 
 * Examples:
 * - "US" → 🇺🇸
 * - "CA" → 🇨🇦  
 * - "KR" → 🇰🇷
 * - "GB" → 🇬🇧
 */
export const getCountryFlag = (countryCode: string): string => {
  if (!countryCode || countryCode.length !== 2) return "🏳️";

  // Convert country code to flag emoji using Unicode regional indicator symbols
  // Each letter is converted to a regional indicator symbol (U+1F1E6 to U+1F1FF)
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map(char => 127397 + char.charCodeAt(0));

  return String.fromCodePoint(...codePoints);
};

/**
 * Format location data with country flag
 * @param geoData - Geo data object containing country and city information
 * @returns Formatted location string with flag emoji
 */
export const formatLocationWithFlag = (geoData: any): string => {
  if (!geoData) return "N/A";

  // Try to get country and city from various field names
  const country = geoData.country || geoData.geoCc;
  const city = geoData.city || geoData.geoCity;

  if (!country) return "N/A";

  // Convert country code to flag emoji
  const flag = getCountryFlag(country);
  return city ? `${flag} ${city}, ${country}` : `${flag} ${country}`;
};

/**
 * Format country with flag
 * @param countryCode - Country code
 * @returns Formatted country string with flag emoji
 */
export const formatCountryWithFlag = (countryCode: string): string => {
  if (!countryCode) return "N/A";
  const flag = getCountryFlag(countryCode);
  return `${flag} ${countryCode}`;
};
