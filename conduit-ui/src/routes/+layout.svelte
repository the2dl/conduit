<script lang="ts">
	import '../app.css';
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { drawer } from '$lib/drawer.svelte';
	import { toast } from '$lib/toast.svelte';
	import PolicyDrawer from '$lib/components/PolicyDrawer.svelte';
	import DlpDrawer from '$lib/components/DlpDrawer.svelte';
	import BulkImportModal from '$lib/components/BulkImportModal.svelte';
	import logoSvg from '$lib/assets/conduit-lockup-on-dark.svg';

	let { children } = $props();

	const navGroups = [
		{
			label: 'Monitor',
			items: [
				{ href: '/', label: 'Overview' },
				{ href: '/traffic', label: 'Traffic' },
				{ href: '/users', label: 'Users' }
			]
		},
		{
			label: 'Control',
			items: [
				{ href: '/policies', label: 'Policies', countKey: 'policy' as const },
				{ href: '/categories', label: 'Categories' },
				{ href: '/dlp', label: 'DLP', countKey: 'dlp' as const }
			]
		},
		{
			label: 'System',
			items: [
				{ href: '/nodes', label: 'Nodes', countKey: 'node' as const },
				{ href: '/settings', label: 'Settings' }
			]
		}
	];

	function getCount(key?: 'policy' | 'dlp' | 'node') {
		if (key === 'policy') return drawer.policyCount ? String(drawer.policyCount) : '';
		if (key === 'dlp') return drawer.dlpCount ? String(drawer.dlpCount) : '';
		if (key === 'node') return drawer.nodeCount ? String(drawer.nodeCount) : '';
		return '';
	}

	function isItemActive(href: string) {
		const path = page.url.pathname;
		if (href === '/') return path === '/';
		if (href === '/traffic') return path === '/traffic' || path === '/logs';
		return path.startsWith(href);
	}

	let modeEnforcing = $derived(
		drawer.config.prevention_mode === 'true' || drawer.config.prevention_mode === '1'
	);

	onMount(() => {
		drawer.refreshGlobal();
		const interval = setInterval(() => {
			drawer.refreshGlobal();
		}, 4000);
		return () => clearInterval(interval);
	});
</script>

<svelte:head>
	<title>conduit</title>
</svelte:head>

<div class="h-screen grid grid-cols-[224px_minmax(0,1fr)] overflow-hidden bg-[#0A0A0B] text-[#E6E6E8]">
	<!-- Left Sidebar -->
	<aside class="flex flex-col border-r border-[#1F1F24] min-h-0 bg-[#0A0A0B]">
		<!-- Logo Row -->
		<div class="h-14 flex items-center px-4.5 border-b border-[#1F1F24]">
			<a href="/" class="flex items-center">
				<img src={logoSvg} alt="conduit" class="h-[17px] w-auto block" />
			</a>
		</div>

		<!-- Nav Groups -->
		<nav class="flex-1 overflow-y-auto p-2.5 py-3.5 flex flex-col gap-4.5">
			{#each navGroups as group}
				<div class="flex flex-col gap-0.5">
					<span
						class="px-2.5 pb-1.5 font-mono text-[10.5px] font-semibold tracking-[0.12em] uppercase text-[#55555C]"
					>
						{group.label}
					</span>
					{#each group.items as item}
						{@const active = isItemActive(item.href)}
						{@const count = getCount(item.countKey)}
						<a
							href={item.href}
							class="relative h-[30px] flex items-center gap-2 px-2.5 rounded-[5px] text-[13px] font-medium text-left no-underline transition-colors
								{active
								? 'bg-[#16161A] text-[#E6E6E8]'
								: 'bg-transparent text-[#A3A3AB] hover:bg-[#16161A] hover:text-[#E6E6E8]'}"
						>
							{#if active}
								<span
									class="absolute -left-2.5 top-[7px] bottom-[7px] w-0.5 rounded-r-[2px] bg-[#ED2377]"
								></span>
							{/if}
							<span class="flex-1">{item.label}</span>
							{#if count}
								<span class="font-mono text-[11px] text-[#55555C]">{count}</span>
							{/if}
						</a>
					{/each}
				</div>
			{/each}
		</nav>

		<!-- Sidebar Footer Card -->
		<a
			href="/settings"
			class="m-2.5 p-2.5 px-3 border border-[#1F1F24] rounded-md bg-[#111113] flex flex-col gap-1.5 text-left text-[#E6E6E8] no-underline hover:border-[#2A2A30] transition-colors"
		>
			<div class="flex items-center gap-2 w-full text-[12.5px] font-medium">
				<span
					class="w-1.5 h-1.5 rounded-full {drawer.health.status === 'healthy'
						? 'bg-[#4ADE80] shadow-[0_0_0_3px_rgba(74,222,128,0.15)]'
						: 'bg-[#FDBA74]'}"
				></span>
				<span>{drawer.health.status}</span>
				<span class="ml-auto font-mono text-[11px] text-[#6B6B73]">v{drawer.health.version}</span>
			</div>
			<div class="flex items-center gap-2 w-full font-mono text-[11px] text-[#6B6B73]">
				<span>mode</span>
				<span
					class="ml-auto px-1.5 py-px rounded-[3px] font-medium
						{modeEnforcing
						? 'bg-[rgba(237,35,119,0.15)] text-[#ED2377]'
						: 'bg-[rgba(253,186,116,0.12)] text-[#FDBA74]'}"
				>
					{modeEnforcing ? 'enforcing' : 'monitor'}
				</span>
			</div>
		</a>
	</aside>

	<!-- Main Content Area -->
	<main class="min-w-0 min-h-0 flex-1 flex flex-col bg-[#0A0A0B] overflow-hidden">
		{@render children()}
	</main>
</div>

<!-- Floating Toast -->
{#if toast.visible}
	<div
		class="fixed bottom-5 left-1/2 -translate-x-1/2 z-50 py-2 px-3.5 border border-[#2A2A30] rounded-lg bg-[#18181C] text-[12.5px] shadow-[0_12px_32px_rgba(0,0,0,0.5)] flex items-center gap-2"
	>
		<span class="w-1.5 h-1.5 rounded-full bg-[#4ADE80]"></span>
		<span>{toast.message}</span>
	</div>
{/if}

<!-- Slide-out Drawer Container -->
{#if drawer.activeSheet}
	<button
		type="button"
		aria-label="Close sheet"
		onclick={() => drawer.close()}
		class="fixed inset-0 bg-[rgba(5,5,6,0.6)] z-40 border-none cursor-default"
	></button>
	<div
		class="fixed top-0 right-0 bottom-0 w-[460px] max-w-full bg-[#0E0E10] border-l border-[#1F1F24] z-50 flex flex-col shadow-[-24px_0_48px_rgba(0,0,0,0.4)]"
	>
		<div class="h-14 shrink-0 flex items-center px-5 border-b border-[#1F1F24]">
			<span class="text-sm font-semibold">
				{#if drawer.activeSheet === 'policy'}
					{drawer.policyDraft.id ? 'Edit policy' : 'New policy'}
				{:else if drawer.activeSheet === 'dlp'}
					{drawer.dlpDraft.id ? 'Edit DLP rule' : 'New DLP rule'}
				{:else if drawer.activeSheet === 'bulk_categories'}
					Bulk import domains
				{/if}
			</span>
			<button
				type="button"
				onclick={() => drawer.close()}
				class="ml-auto w-6.5 h-6.5 border-none rounded bg-transparent text-[#6B6B73] text-[17px] cursor-pointer hover:bg-[#1B1B20] hover:text-[#E6E6E8] flex items-center justify-center"
			>
				&times;
			</button>
		</div>

		{#if drawer.activeSheet === 'policy'}
			<PolicyDrawer />
		{:else if drawer.activeSheet === 'dlp'}
			<DlpDrawer />
		{:else if drawer.activeSheet === 'bulk_categories'}
			<BulkImportModal />
		{/if}
	</div>
{/if}
