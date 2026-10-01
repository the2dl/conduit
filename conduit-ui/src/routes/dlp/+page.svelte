<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type DlpRule } from '$lib/api';
	import { drawer } from '$lib/drawer.svelte';
	import { showToast } from '$lib/toast.svelte';

	let rules = $state<DlpRule[]>([]);
	let loading = $state(true);

	async function loadRules() {
		loading = true;
		try {
			rules = await api.dlp.list();
		} catch {
			/* ignore */
		}
		loading = false;
	}

	async function toggleRule(rule: DlpRule, e: MouseEvent) {
		e.stopPropagation();
		try {
			const updated = { ...rule, enabled: !rule.enabled };
			await api.dlp.update(updated);
			rules = rules.map((r) => (r.id === rule.id ? updated : r));
			showToast(updated.enabled ? `Enabled ${rule.name}` : `Disabled ${rule.name}`);
		} catch (e: any) {
			showToast(e.message || 'Failed to update rule');
		}
	}

	function getActionInfo(action: string) {
		if (action === 'block') return { label: 'BLOCK', color: '#F87171' };
		if (action === 'redact') return { label: 'REDACT', color: '#C084FC' };
		return { label: 'LOG', color: '#FDBA74' };
	}

	function editRule(rule: DlpRule) {
		drawer.openDlp({
			id: rule.id,
			name: rule.name,
			pattern: rule.regex,
			action: rule.action,
			builtin: rule.builtin,
			allowed_domains: rule.allowed_domains
		});
	}

	onMount(() => {
		loadRules();
		drawer.setDlpSavedCallback(loadRules);
	});
</script>

<div class="flex-1 flex flex-col h-full overflow-hidden">
	<!-- Page Header -->
	<header class="h-14 shrink-0 flex items-center gap-3 px-7 border-b border-[#1F1F24]">
		<span class="text-[15px] font-semibold">Data loss prevention</span>
		<span class="text-[12.5px] text-[#6B6B73]">patterns scanned against bodies</span>
		<button
			type="button"
			onclick={() => drawer.openDlp()}
			class="ml-auto h-7 px-3 border-none rounded-md bg-[#ED2377] text-white text-[12.5px] font-medium cursor-pointer hover:bg-[#F23D88] transition-colors"
		>
			New rule
		</button>
	</header>

	<!-- Table Area -->
	<div class="flex-1 overflow-auto p-5 px-7 pb-10">
		<div class="border border-[#1F1F24] rounded-lg overflow-hidden bg-[#111113] text-[13px]">
			<div
				class="grid grid-cols-[minmax(140px,1fr)_minmax(240px,2fr)_64px_70px_50px_36px] gap-3.5 items-center h-8 px-4 bg-[#111113] border-b border-[#1F1F24] font-mono text-[10.5px] tracking-wider uppercase text-[#55555C]"
			>
				<span>Name</span>
				<span>Pattern</span>
				<span>Action</span>
				<span>Source</span>
				<span class="text-right">Hits</span>
				<span>On</span>
			</div>

			{#if loading}
				<div class="p-8 text-xs text-[#6B6B73]">Loading DLP rules...</div>
			{:else if rules.length === 0}
				<div class="p-8 text-xs text-[#6B6B73]">No DLP rules configured.</div>
			{:else}
				{#each rules as r}
					{@const act = getActionInfo(r.action)}
					<div
						role="button"
						tabindex="0"
						onclick={() => editRule(r)}
						onkeydown={(e) => e.key === 'Enter' && editRule(r)}
						class="grid grid-cols-[minmax(140px,1fr)_minmax(240px,2fr)_64px_70px_50px_36px] gap-3.5 items-center h-11 px-4 border-b border-[#151518] last:border-none cursor-pointer transition-colors hover:bg-[#131316] text-left text-[13px]
							{r.enabled ? 'opacity-100' : 'opacity-50'}"
					>
						<span class="text-[13px] font-medium text-[#E6E6E8] truncate flex items-center gap-2">
							<span class="truncate">{r.name}</span>
							{#if r.allowed_domains && r.allowed_domains.length > 0}
								<span class="shrink-0 text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#1A1A20] text-[#8E8E98] border border-[#26262E]" title={r.allowed_domains.join(', ')}>
									{r.allowed_domains.length} exempt
								</span>
							{/if}
						</span>
						<span class="font-mono text-xs text-[#A3A3AB] truncate">{r.regex}</span>
						<span
							class="flex items-center gap-1.5 font-mono text-[10.5px] font-semibold tracking-wider"
							style="color: {act.color};"
						>
							<span class="w-[5px] h-[5px] rounded-full" style="background: {act.color};"></span>
							{act.label}
						</span>
						<span class="font-mono text-[11px] text-[#6B6B73]">
							{r.builtin ? 'built-in' : 'custom'}
						</span>
						<span class="text-right font-mono text-xs text-[#A3A3AB]">{(r.hits || 0).toLocaleString()}</span>

						<!-- On/Off Switch -->
						<button
							type="button"
							aria-label="Toggle rule"
							onclick={(e) => toggleRule(r, e)}
							class="w-7 h-4 border-none rounded-full p-0.5 flex items-center cursor-pointer transition-colors
								{r.enabled ? 'bg-[#ED2377] justify-end' : 'bg-[#2A2A30] justify-start'}"
						>
							<span class="w-3 h-3 rounded-full bg-white block"></span>
						</button>
					</div>
				{/each}
			{/if}
		</div>
	</div>
</div>
