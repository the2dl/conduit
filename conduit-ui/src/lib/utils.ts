import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import type { Snippet } from "svelte";
import type { HTMLAttributes } from "svelte/elements";

export function cn(...inputs: ClassValue[]) {
	return twMerge(clsx(inputs));
}

export type WithoutChildren<T> = T extends { children?: unknown }
	? Omit<T, "children">
	: T;

export type WithoutChild<T> = T extends { child?: unknown; children?: unknown }
	? Omit<T, "child" | "children"> & { children?: Snippet }
	: T;

export type WithoutChildrenOrChild<T> = T extends { child?: unknown; children?: unknown }
	? Omit<T, "child" | "children">
	: T;

export type WithElementRef<T> = T & {
	ref?: HTMLElement | null;
};
