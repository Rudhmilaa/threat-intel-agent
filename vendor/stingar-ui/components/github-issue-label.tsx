"use client";

import type { CSSProperties, ReactNode } from "react";
import { cn } from "@/lib/utils";

/** GitHub issue-label look: tinted pill with border (not a button). */
export type GithubIssueLabelTone =
  | "benign"
  | "malicious"
  | "suspicious"
  | "unknown"
  | "neutral"
  | "blue"
  | "purple";

const TONE_STYLES: Record<
  GithubIssueLabelTone,
  { backgroundColor: string; borderColor: string; color: string }
> = {
  benign: {
    backgroundColor: "#dafbe1",
    borderColor: "#aceebb",
    color: "#1a7f37",
  },
  malicious: {
    backgroundColor: "#ffebe9",
    borderColor: "#ffcecb",
    color: "#cf222e",
  },
  suspicious: {
    backgroundColor: "#fff8c5",
    borderColor: "#fae17d",
    color: "#9a6700",
  },
  unknown: {
    backgroundColor: "#f6f8fa",
    borderColor: "#d0d7de",
    color: "#57606a",
  },
  neutral: {
    backgroundColor: "#f6f8fa",
    borderColor: "#d0d7de",
    color: "#57606a",
  },
  blue: {
    backgroundColor: "#ddf4ff",
    borderColor: "#b6e3ff",
    color: "#0969da",
  },
  purple: {
    backgroundColor: "#fbefff",
    borderColor: "#e8d4ff",
    color: "#8250df",
  },
};

const baseClassName =
  "inline-block max-w-full rounded-full border border-solid px-[7px] py-0 text-[12px] font-medium leading-[18px] cursor-default select-none whitespace-nowrap align-middle shadow-none";

export function outcomeTone(category: string): GithubIssueLabelTone {
  if (category in TONE_STYLES) return category as GithubIssueLabelTone;
  return "unknown";
}

export function GithubIssueLabel({
  children,
  tone = "neutral",
  className,
  title,
}: {
  children: ReactNode;
  tone?: GithubIssueLabelTone;
  className?: string;
  title?: string;
}) {
  const palette = TONE_STYLES[tone] ?? TONE_STYLES.neutral;
  return (
    <span
      className={cn(baseClassName, className)}
      style={palette as CSSProperties}
      title={title}
    >
      {children}
    </span>
  );
}

export function GithubIssueLabelList({
  items,
  tone = "neutral",
}: {
  items: string[];
  tone?: GithubIssueLabelTone;
}) {
  if (!items.length) return null;
  return (
    <span className="inline-flex flex-wrap gap-1">
      {items.map((item) => (
        <GithubIssueLabel key={item} tone={tone}>
          {item}
        </GithubIssueLabel>
      ))}
    </span>
  );
}
