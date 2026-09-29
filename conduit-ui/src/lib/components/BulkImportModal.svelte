<script lang="ts">
	import { drawer } from '$lib/drawer.svelte';
	import { api } from '$lib/api';
	import { showToast } from '$lib/toast.svelte';

	let csvText = $state('');
	let importing = $state(false);

	async function doImport() {
		if (!csvText.trim()) {
			showToast('Please paste CSV content');
			return;
		}
		importing = true;
		try {
			await api.categories.import(csvText.trim());
			drawer.close();
			showToast('Domains imported successfully');
			csvText = '';
			window.location.reload();
		} catch (e: any) {
			showToast(e.message || 'Import failed');
		} finally {
			importing = false;
		}
	}
</script>

<div class="flex-1 overflow-y-auto p-5 flex flex-col gap-4">
	<p class="text-xs text-[#A3A3AB] leading-relaxed">
		Paste a CSV of domain,category (one per line). Supported categories: <span class="font-mono text-[#E6E6E8]">social, gaming, adult, shopping, news_media, technology, search_engine, cdn_infrastructure, banking_finance, healthcare, education, travel_transport, business_services, reference, other</span>.
	</p>
	<textarea
		bind:value={csvText}
		rows="10"
		placeholder="example.com,technology&#10;casino.test,gaming&#10;adultsite.test,adult"
		class="p-2.5 rounded-md border border-[#1F1F24] bg-[#111113] text-[#E6E6E8] outline-none resize-y font-mono text-xs leading-[18px] focus:border-[#ED2377]"
	></textarea>
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
		disabled={importing}
		onclick={doImport}
		class="h-[30px] px-3.5 rounded-md border-none bg-[#ED2377] text-white text-[12.5px] font-medium cursor-pointer hover:bg-[#F23D88] disabled:opacity-50"
	>
		{importing ? 'Importing...' : 'Import CSV'}
	</button>
</div>
