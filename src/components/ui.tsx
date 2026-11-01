import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";
import type { ButtonHTMLAttributes } from "react";
import type { Status } from "@/lib/types";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-full text-sm font-semibold transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        default: "bg-teal text-white hover:bg-teal-ink",
        outline: "border border-line bg-card text-ink hover:bg-paper",
        ghost: "text-ink hover:bg-black/5",
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
  pass: "bg-emerald-50 text-emerald-800 ring-emerald-200",
  warn: "bg-amber-50 text-amber-900 ring-amber-200",
  fail: "bg-red-50 text-red-800 ring-red-200",
  info: "bg-stone-100 text-stone-700 ring-stone-200",
  inconclusive: "bg-stone-100 text-stone-700 ring-stone-200",
};

export function StatusBadge({ status, label }: { status: Status; label: string }) {
  return (
    <span className={cn("inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold ring-1 ring-inset", badgeTone[status])}>
      {label}
    </span>
  );
}
