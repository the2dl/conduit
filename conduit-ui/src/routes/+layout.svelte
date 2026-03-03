<script lang="ts">
	import '../app.css';
	import { page } from '$app/state';
	import { Separator } from '$lib/components/ui/separator';
	import LayoutDashboard from '@lucide/svelte/icons/layout-dashboard';
	import ScrollText from '@lucide/svelte/icons/scroll-text';
	import Layers from '@lucide/svelte/icons/layers';
	import Shield from '@lucide/svelte/icons/shield';
	import UsersIcon from '@lucide/svelte/icons/users';
	import ServerIcon from '@lucide/svelte/icons/server';
	import SettingsIcon from '@lucide/svelte/icons/settings';

	let { children } = $props();

	const nav = [
		{ href: '/', label: 'Dashboard', icon: LayoutDashboard },
		{ href: '/logs', label: 'Logs', icon: ScrollText },
		{ href: '/categories', label: 'Categories', icon: Layers },
		{ href: '/policies', label: 'Policies', icon: Shield },
		{ href: '/users', label: 'Users', icon: UsersIcon },
		{ href: '/nodes', label: 'Nodes', icon: ServerIcon },
		{ href: '/settings', label: 'Settings', icon: SettingsIcon }
	];
</script>

<svelte:head>
	<title>conduit</title>
</svelte:head>

<div class="flex h-screen">
	<aside class="w-60 shrink-0 border-r border-border bg-sidebar flex flex-col">
		<div class="p-5">
			<h1 class="text-xl font-bold bg-gradient-to-br from-primary to-pink-400 bg-clip-text text-transparent">conduit</h1>
			<div class="text-[0.7rem] text-muted-foreground uppercase tracking-widest mt-1">proxy</div>
		</div>
		<Separator />
		<nav class="flex-1 p-3 flex flex-col gap-1">
			{#each nav as item}
				<a
					href={item.href}
					class="flex items-center gap-3 px-3 py-2.5 rounded-md text-sm transition-colors no-underline
						{page.url.pathname === item.href
							? 'bg-primary/15 text-primary'
							: 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'}"
				>
					<item.icon class="size-4" />
					{item.label}
				</a>
			{/each}
		</nav>
	</aside>
	<main class="flex-1 overflow-y-auto p-6">
		{@render children()}
	</main>
</div>
