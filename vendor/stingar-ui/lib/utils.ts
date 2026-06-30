import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"
import { randomBytes } from "crypto";
 
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

function toCamelCase(str: string): string {
  return str.replace(/([-_][a-z])/gi, ($1) => {
    return $1.toUpperCase().replace('-', '').replace('_', '');
  });
}

export function convertSnakeToCamelCase(obj: any): any {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map((item) => convertSnakeToCamelCase(item));
  }

  return Object.keys(obj).reduce((acc: Record<string, any>, key: string) => {
    const camelKey = toCamelCase(key);
    acc[camelKey] = convertSnakeToCamelCase(obj[key]);
    return acc;
  }, {});
}

function toSnakeCase(str: string): string {
  return str.replace(/([A-Z])/g, (match) => `_${match.toLowerCase()}`);
}

export function convertCamelToSnakeCase(obj: any): any {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map((item) => convertCamelToSnakeCase(item));
  }

  return Object.keys(obj).reduce((acc: Record<string, any>, key: string) => {
    const snakeKey = toSnakeCase(key);
    acc[snakeKey] = convertCamelToSnakeCase(obj[key]);
    return acc;
  }, {});
}

export function generateToken(length: number = 16): string {
  return randomBytes(length).toString("hex");
}