<script lang="ts">
	import { drawer } from '$lib/drawer.svelte';

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

	function toggleCat(cat: string) {
		if (drawer.policyDraft.cats.includes(cat)) {
			drawer.policyDraft.cats = drawer.policyDraft.cats.filter((c) => c !== cat);
		} else {
			drawer.policyDraft.cats = [...drawer.policyDraft.cats, cat];
		}
	}

	function split(s: string) {
		return (s || '').split(/[\s,]+/).filter(Boolean);
	}

	let mParts = $derived([
		drawer.policyDraft.cats.length && 'category in [' + drawer.policyDraft.cats.join(', ') + ']',
		split(drawer.policyDraft.domains).length &&
			'host ~ [' + split(drawer.policyDraft.domains).join(', ') + ']'
	].filter(Boolean));

	let who = $derived([
		split(drawer.policyDraft.users).length &&
			'user in [' + split(drawer.policyDraft.users).join(', ') + ']',
		split(drawer.policyDraft.groups).length &&
			'group in [' + split(drawer.policyDraft.groups).join(', ') + ']'
	].filter(Boolean));

	let preview = $derived(
		`${drawer.policyDraft.action} when ${mParts.join(' or ') || '…'}${
			who.length ? ' and ' + who.join(' and ') : ''
		}`
	);
</script>

<div class="flex-1 overflow-y-auto p-5 flex flex-col gap-5">
	<div class="grid grid-cols-[1fr_80px] gap-2.5">
		<label class="flex flex-col gap-1.5">
			<span class="text-xs text-[#A3A3AB]">Name</span>
			<input
				type="text"
				bind:value={drawer.policyDraft.name}
				placeholder="Block social media"
				class="h-8 px-2.5 rounded-md border border-[#1F1F24] bg-[#111113] text-[#E6E6E8] text-[13px] outline-none focus:border-[#ED2377]"
			/>
		</label>
		<label class="flex flex-col gap-1.5">
			<span class="text-xs text-[#A3A3AB]">Priority</span>
			<input
				type="text"
				bind:value={drawer.policyDraft.priority}
				class="h-8 px-2.5 rounded-md border border-[#1F1F24] bg-[#111113] text-[#E6E6E8] font-mono text-[12.5px] outline-none focus:border-[#ED2377]"
			/>
		</label>
	</div>

	<div class="flex flex-col gap-1.5">
		<span class="text-xs text-[#A3A3AB]">Action</span>
		<div class="grid grid-cols-3 gap-0.5 p-0.5 border border-[#1F1F24] rounded-md bg-[#0A0A0B]">
			{#each [
				{ id: 'block', label: 'Block', dot: '#F87171' },
				{ id: 'allow', label: 'Allow', dot: '#4ADE80' },
				{ id: 'log', label: 'Log', dot: '#A3A3AB' }
			] as act}
				<button
					type="button"
					onclick={() => (drawer.policyDraft.action = act.id as any)}
					class="h-7 rounded flex items-center justify-center gap-1.5 text-[12.5px] cursor-pointer transition-colors
						{drawer.policyDraft.action === act.id
						? 'bg-[#1F1F24] text-[#E6E6E8]'
						: 'bg-transparent text-[#6B6B73] hover:text-[#A3A3AB]'}"
				>
					<span class="w-[5px] h-[5px] rounded-full" style="background: {act.dot}"></span>
					{act.label}
				</button>
			{/each}
		</div>
	</div>

	<div class="flex flex-col gap-2">
		<span class="font-mono text-[10.5px] font-semibold tracking-[0.12em] uppercase text-[#55555C]">
			Match any of
		</span>
		<span class="text-xs text-[#A3A3AB]">Categories</span>
		<div class="flex flex-wrap gap-1.5">
			{#each CATS as cat}
				{@const active = drawer.policyDraft.cats.includes(cat)}
				<button
					type="button"
					onclick={() => toggleCat(cat)}
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

	<label class="flex flex-col gap-1.5">
		<span class="text-xs text-[#A3A3AB]">Domains</span>
		<input
			type="text"
			bind:value={drawer.policyDraft.domains}
			placeholder="*.facebook.com twitter.com"
			class="h-8 px-2.5 rounded-md border border-[#1F1F24] bg-[#111113] text-[#E6E6E8] font-mono text-[12.5px] outline-none focus:border-[#ED2377]"
		/>
		<span class="text-[11.5px] text-[#55555C]">Space or comma separated. Wildcards match subdomains.</span>
	</label>

	<div class="flex flex-col gap-2">
		<span class="font-mono text-[10.5px] font-semibold tracking-[0.12em] uppercase text-[#55555C]">
			Apply to
		</span>
		<div class="grid grid-cols-2 gap-2.5">
			<label class="flex flex-col gap-1.5">
				<span class="text-xs text-[#A3A3AB]">Users</span>
				<input
					type="text"
					bind:value={drawer.policyDraft.users}
					placeholder="everyone"
					class="h-8 px-2.5 rounded-md border border-[#1F1F24] bg-[#111113] text-[#E6E6E8] font-mono text-[12.5px] outline-none focus:border-[#ED2377]"
				/>
			</label>
			<label class="flex flex-col gap-1.5">
				<span class="text-xs text-[#A3A3AB]">Groups</span>
				<input
					type="text"
					bind:value={drawer.policyDraft.groups}
					placeholder="all groups"
					class="h-8 px-2.5 rounded-md border border-[#1F1F24] bg-[#111113] text-[#E6E6E8] font-mono text-[12.5px] outline-none focus:border-[#ED2377]"
				/>
			</label>
		</div>
	</div>

	<div
		class="p-2.5 rounded-md border border-[#1F1F24] bg-[#111113] font-mono text-[11.5px] leading-[18px] text-[#A3A3AB] break-all"
	>
		{preview}
	</div>
</div>

<div class="shrink-0 flex justify-end gap-2 p-3 px-5 border-t border-[#1F1F24]">
	<button
		type="button"
		onclick={() => drawer.close()}
		class="h-[30px] px-3 rounded-md border-none bg-transparent text-[#A3A3AB] text-[12.5px] cursor-pointer hover:text-[#E6E6E8]"
	>
		Cancel
	</button>
	<button
		type="button"
		onclick={() => drawer.savePolicy()}
		class="h-[30px] px-3.5 rounded-md border-none bg-[#ED2377] text-white text-[12.5px] font-medium cursor-pointer hover:bg-[#F23D88]"
	>
		Save policy
	</button>
</div>
