<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type CategoryEntry } from '$lib/api';
	import { drawer } from '$lib/drawer.svelte';
	import { showToast } from '$lib/toast.svelte';

	const CATS = [
		'social',
		'gaming',
		'adult',
		'shopping',
		'news_media',
		'technology',
		'search_engine',
		'cdn_infrastructure',
		'banking_finance',
		'healthcare',
		'education',
		'travel_transport',
		'business_services',
		'reference',
		'other'
	];

	const RISKY: Record<string, string> = {
		adult: '#F87171',
		gaming: '#FDBA74',
		social: '#FDBA74'
	};

	let categories = $state<CategoryEntry[]>([]);
	let totalEstimate = $state<number | null>(null);
	let searchQuery = $state('');
	let selectedCatFilter = $state('');
	let loading = $state(true);

	let newDomain = $state('');
	let newCategory = $state('social');

	async function loadCategories() {
		loading = true;
		try {
			const params: Record<string, string> = { limit: '100' };
			if (searchQuery.trim()) params.search = searchQuery.trim();
			if (selectedCatFilter) params.category = selectedCatFilter;

			const res = await api.categories.list(params);
			categories = res.entries || [];
			totalEstimate = res.total_estimate;
		} catch {
			/* ignore */
		}
		loading = false;
	}

	async function addMapping() {
		const d = newDomain.trim().toLowerCase();
		if (!d) return;
		try {
			await api.categories.add({ domain: d, category: newCategory });
			newDomain = '';
			showToast(`${d} → ${newCategory}`);
			await loadCategories();
		} catch (e: any) {
			showToast(e.message || 'Failed to add category mapping');
		}
	}

	async function removeMapping(domain: string) {
		try {
			await api.categories.remove(domain);
			categories = categories.filter((c) => c.domain !== domain);
			showToast(`Removed ${domain}`);
		} catch (e: any) {
			showToast(e.message || 'Failed to remove mapping');
		}
	}

	function onFilterClick(cat: string) {
		selectedCatFilter = selectedCatFilter === cat ? '' : cat;
		loadCategories();
	}

	onMount(() => {
		// Check URL search params for domain prefill
		const params = new URLSearchParams(window.location.search);
		const dom = params.get('search') || params.get('domain');
		if (dom) {
			searchQuery = dom;
			newDomain = dom;
		}
		loadCategories();
	});
</script>

<div class="flex-1 flex flex-col h-full overflow-hidden">
	<!-- Page Header -->
	<header class="h-14 shrink-0 flex items-center gap-3 px-7 border-b border-[#1F1F24]">
		<span class="text-[15px] font-semibold">Categories</span>
		<span class="text-[#6B6B73]">
			~{totalEstimate ? totalEstimate.toLocaleString() : '1,000,021'} domain mappings
		</span>
		<button
			type="button"
			onclick={() => drawer.openBulkCategories()}
			class="ml-auto h-7 px-3 border border-[#2A2A30] rounded-md bg-transparent text-[#E6E6E8] text-[12.5px] cursor-pointer hover:bg-[#16161A] transition-colors"
		>
			Bulk import
		</button>
	</header>

	<!-- Toolbar Area -->
	<div class="shrink-0 flex flex-col gap-2.5 p-3 px-7 border-b border-[#1F1F24]">
		<div class="flex flex-wrap gap-2.5 items-center">
			<!-- Search input -->
			<div
				class="flex-1 min-w-[220px] max-w-[420px] h-[30px] flex items-center gap-2 px-2.5 border border-[#1F1F24] rounded-md bg-[#111113]"
			>
				<span class="font-mono text-[#55555C]">/</span>
				<input
					type="text"
					bind:value={searchQuery}
					onkeydown={(e) => e.key === 'Enter' && loadCategories()}
					placeholder="Look up a domain…"
					class="flex-1 border-none outline-none bg-transparent text-[#E6E6E8] font-mono text-[12.5px]"
				/>
			</div>

			<span class="w-px h-5 bg-[#1F1F24] hidden sm:block"></span>

			<!-- Inline Add -->
			<input
				type="text"
				bind:value={newDomain}
				placeholder="add example.com"
				class="w-45 h-[30px] px-2.5 border border-[#1F1F24] rounded-md bg-[#111113] text-[#E6E6E8] outline-none font-mono text-[12.5px] focus:border-[#ED2377]"
			/>
			<select
				bind:value={newCategory}
				class="h-[30px] px-2 border border-[#1F1F24] rounded-md bg-[#111113] text-[#E6E6E8] font-mono text-xs outline-none focus:border-[#ED2377]"
			>
				{#each CATS as cat}
					<option value={cat}>{cat}</option>
				{/each}
			</select>
			<button
				type="button"
				onclick={addMapping}
				class="h-[30px] px-3 border-none rounded-md bg-[#ED2377] text-white text-[12.5px] font-medium cursor-pointer hover:bg-[#F23D88] transition-colors"
			>
				Add
			</button>
		</div>

		<!-- Category Filter Chips -->
		<div class="flex flex-wrap gap-1.5">
			<button
				type="button"
				onclick={() => onFilterClick('')}
				class="h-6 px-2.5 rounded-full border font-mono text-[11.5px] cursor-pointer transition-colors
					{selectedCatFilter === ''
					? 'bg-[#E6E6E8] text-[#0A0A0B] border-[#E6E6E8]'
					: 'bg-transparent text-[#A3A3AB] border-[#2A2A30] hover:border-[#3A3A42]'}"
			>
				all
			</button>
			{#each CATS as cat}
				{@const active = selectedCatFilter === cat}
				<button
					type="button"
					onclick={() => onFilterClick(cat)}
					class="h-6 px-2.5 rounded-full border font-mono text-[11.5px] cursor-pointer transition-colors
						{active
						? 'bg-[#E6E6E8] text-[#0A0A0B] border-[#E6E6E8]'
						: 'bg-transparent text-[#A3A3AB] border-[#2A2A30] hover:border-[#3A3A42]'}"
				>
					{cat}
				</button>
			{/each}
		</div>
	</div>

	<!-- Table Area -->
	<div class="flex-1 overflow-auto">
		{#if loading}
			<div class="p-12 px-7 text-[#6B6B73]">Loading domain mappings...</div>
		{:else if categories.length === 0}
			<div class="p-12 px-7 text-[#6B6B73]">
				Not in the local set. Add a mapping above to categorize it.
			</div>
		{:else}
			{#each categories as m}
				{@const color = RISKY[m.category] || '#A3A3AB'}
				<div
					class="grid grid-cols-[minmax(200px,1fr)_200px_80px_28px] gap-4 items-center h-[34px] px-7 border-b border-[#151518] font-mono text-xs hover:bg-[#131316] transition-colors"
				>
					<span class="text-[#E6E6E8] truncate">{m.domain}</span>
					<span>
						<span
							class="px-1.5 py-px rounded-[3px] bg-[#16161A] border border-[#1F1F24] text-[11px]"
							style="color: {color};"
						>
							{m.category}
						</span>
					</span>
					<span class="text-[11px] {m.source === 'manual' ? 'text-[#ED2377] font-medium' : 'text-[#55555C]'}">{m.source || 'feed'}</span>
					<button
						type="button"
						aria-label="Remove mapping"
						onclick={() => removeMapping(m.domain)}
						class="w-6 h-6 border-none rounded bg-transparent text-[#55555C] text-[15px] cursor-pointer hover:bg-[#1B1B20] hover:text-[#F87171] flex items-center justify-center transition-colors"
					>
						&times;
					</button>
				</div>
			{/each}
		{/if}
	</div>
</div>
