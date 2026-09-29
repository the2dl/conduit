<script lang="ts">
	import { drawer } from '$lib/drawer.svelte';

	interface Segment {
		text: string;
		matched: boolean;
	}

	let analysis = $derived.by(() => {
		const pattern = drawer.dlpDraft.pattern;
		const sample = drawer.dlpDraft.sample;
		if (!pattern) {
			return {
				regexError: '',
				matchCount: 0,
				segments: [{ text: sample, matched: false }]
			};
		}

		let re: RegExp;
		try {
			re = new RegExp(pattern, 'g');
		} catch (e: any) {
			return {
				regexError: e.message.replace(/^Invalid regular expression: /, ''),
				matchCount: 0,
				segments: [{ text: sample, matched: false }]
			};
		}

		const segs: Segment[] = [];
		let lastIdx = 0;
		let m: RegExpExecArray | null;
		let count = 0;

		try {
			while ((m = re.exec(sample)) !== null && m[0].length > 0) {
				if (m.index > lastIdx) {
					segs.push({ text: sample.slice(lastIdx, m.index), matched: false });
				}
				segs.push({ text: m[0], matched: true });
				count++;
				lastIdx = m.index + m[0].length;
				if (!re.global) break;
			}
			if (lastIdx < sample.length) {
				segs.push({ text: sample.slice(lastIdx), matched: false });
			}
		} catch {
			return {
				regexError: '',
				matchCount: 0,
				segments: [{ text: sample, matched: false }]
			};
		}

		return {
			regexError: '',
			matchCount: count,
			segments: segs
		};
	});

	let regexError = $derived(analysis.regexError);
	let matchCount = $derived(analysis.matchCount);
	let segments = $derived(analysis.segments);

	let message = $derived(
		regexError
			? regexError
			: drawer.dlpDraft.pattern
			? `${matchCount} match${matchCount === 1 ? '' : 'es'} in sample`
			: 'Enter a pattern'
	);
</script>

<div class="flex-1 overflow-y-auto p-5 flex flex-col gap-5">
	<label class="flex flex-col gap-1.5">
		<span class="text-xs text-[#A3A3AB]">Name</span>
		<input
			type="text"
			bind:value={drawer.dlpDraft.name}
			placeholder="Internal project IDs"
			class="h-8 px-2.5 rounded-md border border-[#1F1F24] bg-[#111113] text-[#E6E6E8] text-[13px] outline-none focus:border-[#ED2377]"
		/>
	</label>

	<label class="flex flex-col gap-1.5">
		<span class="text-xs text-[#A3A3AB]">Pattern · regex</span>
		<input
			type="text"
			bind:value={drawer.dlpDraft.pattern}
			class="h-8 px-2.5 rounded-md border font-mono text-[12.5px] bg-[#111113] text-[#E6E6E8] outline-none
				{regexError ? 'border-[#F87171]' : 'border-[#1F1F24] focus:border-[#ED2377]'}"
		/>
		<span
			class="text-[11.5px]
				{regexError ? 'text-[#F87171]' : matchCount > 0 ? 'text-[#FDBA74]' : 'text-[#55555C]'}"
		>
			{message}
		</span>
	</label>

	<div class="flex flex-col gap-1.5">
		<span class="text-xs text-[#A3A3AB]">On match</span>
		<div class="grid grid-cols-3 gap-0.5 p-0.5 border border-[#1F1F24] rounded-md bg-[#0A0A0B]">
			{#each [
				{ id: 'log', label: 'Log', dot: '#A3A3AB' },
				{ id: 'block', label: 'Block', dot: '#F87171' },
				{ id: 'redact', label: 'Redact', dot: '#C084FC' }
			] as act}
				<button
					type="button"
					onclick={() => (drawer.dlpDraft.action = act.id as any)}
					class="h-7 rounded flex items-center justify-center gap-1.5 text-[12.5px] cursor-pointer transition-colors
						{drawer.dlpDraft.action === act.id
						? 'bg-[#1F1F24] text-[#E6E6E8]'
						: 'bg-transparent text-[#6B6B73] hover:text-[#A3A3AB]'}"
				>
					<span class="w-[5px] h-[5px] rounded-full" style="background: {act.dot}"></span>
					{act.label}
				</button>
			{/each}
		</div>
	</div>

	<div class="flex flex-col gap-1.5">
		<span class="text-xs text-[#A3A3AB]">Test against sample</span>
		<textarea
			bind:value={drawer.dlpDraft.sample}
			rows="3"
			class="p-2.5 rounded-md border border-[#1F1F24] bg-[#111113] text-[#E6E6E8] outline-none resize-y font-mono text-xs leading-[18px] focus:border-[#ED2377]"
		></textarea>
		<div
			class="p-2.5 px-3 rounded-md border border-[#1F1F24] bg-[#0A0A0B] font-mono text-xs leading-5 whitespace-pre-wrap break-all min-h-[48px]"
		>
			{#each segments as seg}
				{#if seg.matched}
					<span class="bg-[rgba(253,186,116,0.2)] text-[#FDBA74] rounded-[2px]">{seg.text}</span>
				{:else}
					<span class="text-[#A3A3AB]">{seg.text}</span>
				{/if}
			{/each}
		</div>
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
		onclick={() => drawer.saveDlp()}
		class="h-[30px] px-3.5 rounded-md border-none bg-[#ED2377] text-white text-[12.5px] font-medium cursor-pointer hover:bg-[#F23D88]"
	>
		Save rule
	</button>
</div>
