<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type CategoryEntry } from '$lib/api';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import { Textarea } from '$lib/components/ui/textarea';
	import * as Card from '$lib/components/ui/card';
	import * as Table from '$lib/components/ui/table';

	let categories = $state<CategoryEntry[]>([]);
	let cursor = $state<string | null>(null);
	let totalEstimate = $state<number | null>(null);
	let searchQuery = $state('');
	let categoryFilter = $state('');
	let loading = $state(false);

	let newDomain = $state('');
	let newCategory = $state('');
	let bulkText = $state('');
	let showBulk = $state(false);

	async function load(append = false) {
		loading = true;
		try {
			const params: Record<string, string> = { limit: '100' };
			if (append && cursor) params.cursor = cursor;
			if (searchQuery) params.search = searchQuery;
			if (categoryFilter) params.category = categoryFilter;

			const result = await api.categories.list(params);
			if (append) {
				categories = [...categories, ...result.entries];
			} else {
				categories = result.entries;
			}
			cursor = result.next_cursor;
			totalEstimate = result.total_estimate;
		} catch { /* ignore */ }
		loading = false;
	}

	function search() {
		cursor = null;
		load();
	}

	async function add() {
		if (!newDomain || !newCategory) return;
		await api.categories.add({ domain: newDomain, category: newCategory });
		newDomain = '';
		newCategory = '';
		await load();
	}

	async function remove(domain: string) {
		await api.categories.remove(domain);
		categories = categories.filter(c => c.domain !== domain);
	}

	async function importBulk() {
		if (!bulkText.trim()) return;
		await api.categories.import(bulkText);
		bulkText = '';
		showBulk = false;
		await load();
	}

	onMount(() => load());
</script>

<div class="mb-6">
	<h2 class="text-2xl font-semibold">Categories</h2>
	<p class="text-sm text-muted-foreground mt-1">
		Manage domain-to-category mappings
		{#if totalEstimate}
			<span class="text-muted-foreground"> &middot; ~{totalEstimate.toLocaleString()} total keys</span>
		{/if}
	</p>
</div>

<div class="flex flex-wrap items-center gap-3 mb-4">
	<Input type="text" placeholder="Search domains..." bind:value={searchQuery} onkeydown={(e) => e.key === 'Enter' && search()} class="flex-1 min-w-[200px]" />
	<Input type="text" placeholder="Filter by category..." bind:value={categoryFilter} onkeydown={(e) => e.key === 'Enter' && search()} class="min-w-[160px]" />
	<Button onclick={search}>Search</Button>
	<Button variant="outline" onclick={() => { searchQuery = ''; categoryFilter = ''; search(); }}>Clear</Button>
</div>

<div class="flex flex-wrap items-center gap-3 mb-4">
	<Input type="text" placeholder="Domain (e.g. facebook.com)" bind:value={newDomain} class="flex-1 min-w-[200px]" />
	<Input type="text" placeholder="Category (e.g. social)" bind:value={newCategory} class="min-w-[160px]" />
	<Button onclick={add}>Add</Button>
	<Button variant="outline" onclick={() => showBulk = !showBulk}>
		{showBulk ? 'Hide' : 'Bulk Import'}
	</Button>
</div>

{#if showBulk}
	<Card.Root class="mb-4">
		<Card.Content class="pt-6">
			<div class="space-y-2">
				<Label for="bulk-import">Paste CSV (domain,category per line)</Label>
				<Textarea id="bulk-import" rows={6} class="font-mono text-sm" bind:value={bulkText} placeholder="facebook.com,social&#10;twitter.com,social&#10;malware.example.com,malware" />
			</div>
			<Button onclick={importBulk} class="mt-3">Import</Button>
		</Card.Content>
	</Card.Root>
{/if}

<Card.Root class="overflow-x-auto">
	<Card.Content class="pt-6">
		{#if loading && categories.length === 0}
			<p class="text-sm text-muted-foreground">Loading...</p>
		{:else if categories.length === 0}
			<p class="text-sm text-muted-foreground">No categories found</p>
		{:else}
			<Table.Root>
				<Table.Header>
					<Table.Row>
						<Table.Head>Domain</Table.Head>
						<Table.Head>Category</Table.Head>
						<Table.Head>Actions</Table.Head>
					</Table.Row>
				</Table.Header>
				<Table.Body>
					{#each categories as cat}
						<Table.Row>
							<Table.Cell class="font-mono">{cat.domain}</Table.Cell>
							<Table.Cell><span class="badge-log px-2 py-0.5 rounded text-xs font-semibold uppercase">{cat.category}</span></Table.Cell>
							<Table.Cell>
								<Button variant="destructive" size="sm" onclick={() => remove(cat.domain)}>Remove</Button>
							</Table.Cell>
						</Table.Row>
					{/each}
				</Table.Body>
			</Table.Root>

			<div class="mt-4 flex items-center gap-4">
				<span class="text-xs text-muted-foreground">Showing {categories.length} entries</span>
				{#if cursor}
					<Button variant="outline" size="sm" onclick={() => load(true)} disabled={loading}>
						{loading ? 'Loading...' : 'Load More'}
					</Button>
				{/if}
			</div>
		{/if}
	</Card.Content>
</Card.Root>
