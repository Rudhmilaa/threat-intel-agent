import { use } from "react";

type IconProps = {
  iconId: string;
  className?: string;
  size?: string;
  ariaLabel?: string;
};

export function Icon({ iconId, className = "", size = "4", ariaLabel }: IconProps) {
  const sizeClass = `w-${size} h-${size}`;
  return (
    <svg
      className={`${sizeClass} ${className}`}
      style={{ minWidth: size === "10" ? "40px" : undefined }}
      aria-label={ariaLabel}
      role={ariaLabel ? "img" : "presentation"}
      aria-hidden={!ariaLabel}
    >
      <use href={`/images/icons.svg#${iconId}`} width="100%" height="100%" />
    </svg>
  );
}
