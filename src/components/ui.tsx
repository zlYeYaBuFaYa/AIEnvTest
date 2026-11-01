import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";
import type { ButtonHTMLAttributes } from "react";
import type { Status } from "@/lib/types";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-full text-sm font-semibold transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        default: "bg-teal text-on-teal hover:bg-teal-ink",
        outline: "border border-line bg-card text-ink hover:bg-paper",
        ghost: "text-ink hover:bg-hover",
      },
      size: {
        default: "h-11 px-5",
        sm: "h-9 px-3 text-[13px]",
      },
    },
    defaultVariants: { variant: "default", size: "default" },
  },
);

export function Button({
  className,
  variant,
  size,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & VariantProps<typeof buttonVariants>) {
  return <button className={cn(buttonVariants({ variant, size }), className)} {...props} />;
}

const badgeTone: Record<Status, string> = {
  pass: "bg-status-pass-bg text-status-pass-ink ring-status-pass-border/30",
  warn: "bg-status-warn-bg text-status-warn-ink ring-status-warn-border/30",
  fail: "bg-status-fail-bg text-status-fail-ink ring-status-fail-border/30",
  info: "bg-status-neutral-bg text-status-neutral-ink ring-status-neutral-border/30",
  inconclusive: "bg-status-neutral-bg text-status-neutral-ink ring-status-neutral-border/30",
};

export function StatusBadge({ status, label }: { status: Status; label: string }) {
  return (
    <span className={cn("inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold ring-1 ring-inset", badgeTone[status])}>
      {label}
    </span>
  );
}
