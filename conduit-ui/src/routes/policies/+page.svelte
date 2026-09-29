<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type PolicyRule } from '$lib/api';
	import { drawer } from '$lib/drawer.svelte';
	import { showToast } from '$lib/toast.svelte';

	let policies = $state<PolicyRule[]>([]);
	let loading = $state(true);

	async function loadPolicies() {
		loading = true;
		try {
			const res = await api.policies.list();
			policies = (res || []).sort((a, b) => a.priority - b.priority);
		} catch {
			/* ignore */
		}
		loading = false;
	}

	async function togglePolicy(policy: PolicyRule) {
		try {
			const updated = { ...policy, enabled: !policy.enabled };
			await api.policies.update(updated);
			policies = policies.map((p) => (p.id === policy.id ? updated : p));
			showToast(updated.enabled ? `Enabled ${policy.name}` : `Disabled ${policy.name}`);
		} catch (e: any) {
			showToast(e.message || 'Failed to update policy');
		}
	}

	async function deletePolicy(policy: PolicyRule) {
		try {
			await api.policies.remove(policy.id);
			policies = policies.filter((p) => p.id !== policy.id);
			drawer.refreshGlobal();
			showToast('Policy removed');
		} catch (e: any) {
			showToast(e.message || 'Failed to delete policy');
		}
	}

	function getActionInfo(action: string) {
		if (action === 'block') return { label: 'BLOCK', color: '#F87171' };
		if (action === 'allow') return { label: 'ALLOW', color: '#4ADE80' };
		return { label: 'LOG', color: '#A3A3AB' };
	}

	let modeEnforcing = $derived(
		drawer.config.prevention_mode === 'true' || drawer.config.prevention_mode === '1'
	);

	const templates = [
		{
			name: 'Block social media',
			action: 'block' as const,
			cats: ['social'],
			label: 'BLOCK',
			color: '#F87171',
			match: 'category: social'
		},
		{
			name: 'Block adult & gambling',
			action: 'block' as const,
			cats: ['adult', 'gaming'],
			label: 'BLOCK',
			color: '#F87171',
			match: 'category: adult, gaming'
		},
		{
			name: 'Log shopping',
			action: 'log' as const,
			cats: ['shopping'],
			label: 'LOG',
			color: '#A3A3AB',
			match: 'category: shopping'
		}
	];

	onMount(() => {
		loadPolicies();
		drawer.setPolicySavedCallback(loadPolicies);
	});
</script>

<div class="flex-1 flex flex-col h-full overflow-hidden">
	<!-- Page Header -->
	<header class="h-14 shrink-0 flex items-center gap-3 px-7 border-b border-[#1F1F24]">
		<span class="text-[15px] font-semibold">Policies</span>
		<span class="text-[#6B6B73]">evaluated top to bottom &middot; first match wins</span>
		<button
			type="button"
			onclick={() => drawer.openPolicy()}
			class="ml-auto h-7 px-3 border-none rounded-md bg-[#ED2377] text-white text-[12.5px] font-medium cursor-pointer hover:bg-[#F23D88] transition-colors"
		>
			New policy
		</button>
	</header>

	<!-- Content Area -->
	<div class="flex-1 overflow-auto p-5 px-7 pb-10 flex flex-col gap-4">
		<!-- Warning Banner when Prevention Mode is Off -->
		{#if !modeEnforcing}
			<div
				class="flex items-center gap-2.5 p-2.5 px-3.5 border border-[rgba(253,186,116,0.25)] rounded-md bg-[rgba(253,186,116,0.06)] text-[12.5px]"
			>
				<span class="w-1.5 h-1.5 rounded-full bg-[#FDBA74]"></span>
				<span>Prevention mode is off.</span>
				<span class="text-[#A3A3AB]">Block policies are logged, not enforced.</span>
				<a href="/settings" class="ml-auto text-[#FDBA74] text-[12.5px] no-underline hover:underline">
					Settings &rarr;
				</a>
			</div>
		{/if}

		{#if loading}
			<div class="p-12 text-[#6B6B73]">Loading policies...</div>
		{:else if policies.length === 0}
			<!-- Empty State with Templates -->
			<div class="border border-dashed border-[#2A2A30] rounded-lg p-7 flex flex-col gap-4.5">
				<div class="flex flex-col gap-1">
					<span class="text-sm font-semibold text-[#E6E6E8]">No policies yet</span>
					<span class="text-[#6B6B73]">All traffic is allowed and logged. Start from a template or write your own.</span>
				</div>
				<div class="grid grid-cols-3 gap-2.5">
					{#each templates as t}
						<button
							type="button"
							onclick={() => drawer.openPolicy({ name: t.name, action: t.action, cats: t.cats })}
							class="p-3.5 border border-[#1F1F24] rounded-md bg-[#111113] flex flex-col gap-1.5 text-left cursor-pointer hover:border-[#3A3A42] transition-colors text-[#E6E6E8]"
						>
							<div class="flex items-center gap-2 w-full font-medium">
								<span>{t.name}</span>
								<span
									class="ml-auto font-mono text-[10.5px] font-semibold tracking-wider"
									style="color: {t.color};"
								>
									{t.label}
								</span>
							</div>
							<span class="font-mono text-[11.5px] text-[#6B6B73]">{t.match}</span>
						</button>
					{/each}
				</div>
			</div>
		{:else}
			<!-- Policies Table -->
			<div class="border border-[#1F1F24] rounded-lg overflow-hidden bg-[#111113]">
				<div
					class="grid grid-cols-[40px_minmax(160px,1fr)_64px_minmax(200px,2fr)_50px_36px_28px] gap-3.5 items-center h-8 px-4 bg-[#111113] border-b border-[#1F1F24] font-mono text-[10.5px] tracking-wider uppercase text-[#55555C]"
				>
					<span>Pri</span>
					<span>Name</span>
					<span>Action</span>
					<span>Match</span>
					<span class="text-right">Hits</span>
					<span>On</span>
					<span></span>
				</div>

				{#each policies as p}
					{@const act = getActionInfo(p.action)}
					{@const chips = [
						...(p.categories || []),
						...(p.domains || []),
						...(p.users || []).map((u) => '@' + u),
						...(p.groups || []).map((g) => '#' + g)
					]}
					<div
						class="grid grid-cols-[40px_minmax(160px,1fr)_64px_minmax(200px,2fr)_50px_36px_28px] gap-3.5 items-center min-h-[44px] px-4 border-b border-[#151518] last:border-none transition-colors hover:bg-[#131316]
							{p.enabled ? 'opacity-100' : 'opacity-50'}"
					>
						<span class="font-mono text-[#6B6B73]">{p.priority}</span>
						<span class="font-medium text-[#E6E6E8]">{p.name}</span>
						<span
							class="flex items-center gap-1.5 font-mono text-[10.5px] font-semibold tracking-wider"
							style="color: {act.color};"
						>
							<span class="w-[5px] h-[5px] rounded-full" style="background: {act.color};"></span>
							{act.label}
						</span>
						<div class="flex flex-wrap gap-1 py-2">
							{#each chips as chip}
								<span
									class="px-1.5 py-px rounded-[3px] bg-[#16161A] border border-[#1F1F24] font-mono text-[11px] text-[#A3A3AB]"
								>
									{chip}
								</span>
							{/each}
						</div>
						<span class="text-right font-mono text-[#A3A3AB]">{(p.hits || 0).toLocaleString()}</span>

						<!-- On/Off Switch -->
						<button
							type="button"
							aria-label="Toggle policy"
							onclick={() => togglePolicy(p)}
							class="w-7 h-4 border-none rounded-full p-0.5 flex items-center cursor-pointer transition-colors
								{p.enabled ? 'bg-[#ED2377] justify-end' : 'bg-[#2A2A30] justify-start'}"
						>
							<span class="w-3 h-3 rounded-full bg-white block"></span>
						</button>

						<!-- Delete Button -->
						<button
							type="button"
							aria-label="Delete policy"
							onclick={() => deletePolicy(p)}
							class="w-6 h-6 border-none rounded bg-transparent text-[#55555C] text-[15px] cursor-pointer hover:bg-[#1B1B20] hover:text-[#F87171] flex items-center justify-center transition-colors"
						>
							&times;
						</button>
					</div>
				{/each}
			</div>
		{/if}
	</div>
</div>
