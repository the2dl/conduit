<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type LogEntry } from '$lib/api';
	import { drawer } from '$lib/drawer.svelte';
	import { showToast } from '$lib/toast.svelte';

	let logs = $state<LogEntry[]>([]);
	let searchQuery = $state('');
	let selectedAction = $state<'all' | 'allow' | 'block' | 'dlp'>('all');
	let selectedLog = $state<LogEntry | null>(null);
	let interval: ReturnType<typeof setInterval>;

	async function fetchLogs() {
		try {
			logs = await api.logs({ limit: '500' });
		} catch {
			/* ignore */
		}
	}

	function exportCsv() {
		window.open('/api/v1/export/logs?format=csv', '_blank');
		showToast(`Exported ${filteredLogs.length} rows`);
	}

	function formatTime(ts: string) {
		const d = new Date(ts);
		return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
	}

	function getActionInfo(log: LogEntry) {
		const isDlp = log.block_reason?.toLowerCase().includes('dlp');
		if (isDlp) {
			return { label: 'DLP', color: '#FDBA74', bg: 'rgba(253,186,116,0.12)' };
		}
		if (log.action === 'block') {
			return { label: 'BLOCK', color: '#F87171', bg: 'rgba(248,113,113,0.12)' };
		}
		if (log.action === 'log') {
			return { label: 'LOG', color: '#A3A3AB', bg: 'rgba(163,163,171,0.12)' };
		}
		return { label: 'ALLOW', color: '#6B6B73', bg: '#1B1B20' };
	}

	let filteredLogs = $derived.by(() => {
		const q = searchQuery.trim().toLowerCase();
		return logs.filter((l) => {
			const isDlp = l.block_reason?.toLowerCase().includes('dlp');
			if (selectedAction === 'allow' && l.action !== 'allow') return false;
			if (selectedAction === 'block' && (l.action !== 'block' || isDlp)) return false;
			if (selectedAction === 'dlp' && !isDlp) return false;

			if (!q) return true;
			const hostMatch = l.host?.toLowerCase().includes(q);
			const pathMatch = l.path?.toLowerCase().includes(q);
			const userMatch = (l.username || l.client_ip || '').toLowerCase().includes(q);
			const catMatch = (l.category || '').toLowerCase().includes(q);
			return hostMatch || pathMatch || userMatch || catMatch;
		});
	});

	let counts = $derived.by(() => {
		let allow = 0, block = 0, dlp = 0;
		for (const l of logs) {
			const isDlp = l.block_reason?.toLowerCase().includes('dlp');
			if (isDlp) dlp++;
			else if (l.action === 'block') block++;
			else if (l.action === 'allow') allow++;
		}
		return { all: logs.length, allow, block, dlp };
	});

	function blockHost(host: string) {
		drawer.openPolicy({
			name: `Block ${host}`,
			domains: host,
			action: 'block'
		});
	}

	onMount(() => {
		fetchLogs();
		interval = setInterval(fetchLogs, 2500);
		return () => clearInterval(interval);
	});
</script>

<div class="flex-1 flex flex-col h-full overflow-hidden">
	<!-- Page Header -->
	<header class="h-14 shrink-0 flex items-center gap-3 px-7 border-b border-[#1F1F24]">
		<span class="text-[15px] font-semibold">Traffic</span>
		<span class="text-[#6B6B73]">{filteredLogs.length} requests</span>
		<button
			type="button"
			onclick={exportCsv}
			class="ml-auto h-7 px-3 border border-[#2A2A30] rounded-md bg-transparent text-[#E6E6E8] text-[12.5px] cursor-pointer hover:bg-[#16161A] transition-colors"
		>
			Export CSV
		</button>
	</header>

	<!-- Filter Bar -->
	<div class="shrink-0 flex items-center gap-2.5 px-7 py-2.5 border-b border-[#1F1F24]">
		<div
			class="flex-1 max-w-[560px] h-[30px] flex items-center gap-2 px-2.5 border border-[#1F1F24] rounded-md bg-[#111113]"
		>
			<span class="font-mono text-[#55555C]">/</span>
			<input
				type="text"
				bind:value={searchQuery}
				placeholder="Filter host, path, user, category…"
				class="flex-1 border-none outline-none bg-transparent text-[#E6E6E8] font-mono text-[12.5px]"
			/>
		</div>

		<div class="flex gap-0.5 p-0.5 border border-[#1F1F24] rounded-md bg-[#0A0A0B]">
			{#each [
				{ id: 'all', label: 'All', count: counts.all },
				{ id: 'allow', label: 'Allow', count: counts.allow },
				{ id: 'block', label: 'Block', count: counts.block },
				{ id: 'dlp', label: 'DLP', count: counts.dlp }
			] as const as tab}
				<button
					type="button"
					onclick={() => (selectedAction = tab.id)}
					class="h-6 px-2.5 flex items-center gap-1.5 border-none rounded text-xs cursor-pointer transition-colors
						{selectedAction === tab.id
						? 'bg-[#1F1F24] text-[#E6E6E8]'
						: 'bg-transparent text-[#6B6B73] hover:text-[#A3A3AB]'}"
				>
					{tab.label}
					<span class="font-mono text-[10.5px] text-[#6B6B73]">{tab.count}</span>
				</button>
			{/each}
		</div>

		<span class="ml-auto flex items-center gap-1.5 font-mono text-[11px] text-[#6B6B73]">
			<span class="w-1.5 h-1.5 rounded-full bg-[#4ADE80] animate-pulse"></span>
			live
		</span>
	</div>

	<!-- Main Traffic Table + Detail Panel -->
	<div class="flex-1 min-h-0 flex overflow-hidden">
		<!-- Table Scroll Area -->
		<div class="flex-1 min-w-0 overflow-auto">
			<div
				class="grid grid-cols-[72px_60px_44px_minmax(160px,1.3fr)_minmax(160px,1.5fr)_72px_130px_36px] gap-3 items-center h-8 px-7 sticky top-0 bg-[#0A0A0B] border-b border-[#1F1F24] font-mono text-[10.5px] tracking-wider uppercase text-[#55555C] z-10"
			>
				<span>Time</span>
				<span>Action</span>
				<span>Meth</span>
				<span>Host</span>
				<span>Path</span>
				<span>User</span>
				<span>Category</span>
				<span class="text-right">Code</span>
			</div>

			{#if filteredLogs.length === 0}
				<div class="p-12 px-7 text-[#6B6B73]">No requests match. Loosen the filter or switch to All.</div>
			{:else}
				{#each filteredLogs as log (log.id)}
					{@const act = getActionInfo(log)}
					{@const isSelected = selectedLog?.id === log.id}
					<button
						type="button"
						onclick={() => (selectedLog = isSelected ? null : log)}
						class="w-full grid grid-cols-[72px_60px_44px_minmax(160px,1.3fr)_minmax(160px,1.5fr)_72px_130px_36px] gap-3 items-center h-8 px-7 border-b border-[#151518] border-t-0 border-x-0 font-mono text-xs text-left cursor-pointer transition-colors
							{isSelected ? 'bg-[#16161A]' : 'bg-transparent hover:bg-[#131316]'}"
					>
						<span class="text-[#6B6B73]">{formatTime(log.timestamp)}</span>
						<span
							class="flex items-center gap-1.5 text-[10.5px] font-semibold tracking-wider"
							style="color: {act.color};"
						>
							<span class="w-[5px] h-[5px] rounded-full" style="background: {act.color};"></span>
							{act.label}
						</span>
						<span class="text-[#A3A3AB]">{log.method}</span>
						<span class="truncate text-[#E6E6E8]">{log.host}</span>
						<span class="truncate text-[#6B6B73]">{log.path}</span>
						<span class="truncate text-[#A3A3AB]">{log.username || log.client_ip}</span>
						<span class="truncate text-[#A3A3AB]">{log.category || '—'}</span>
						<span
							class="text-right {log.status_code >= 400 ? 'text-[#F87171]' : 'text-[#6B6B73]'}"
						>
							{log.status_code}
						</span>
					</button>
				{/each}
			{/if}
		</div>

		<!-- 380px Detail Drawer -->
		{#if selectedLog}
			{@const act = getActionInfo(selectedLog)}
			<div
				class="w-[380px] shrink-0 border-l border-[#1F1F24] bg-[#0E0E10] overflow-y-auto flex flex-col shadow-[-12px_0_24px_rgba(0,0,0,0.3)] z-20"
			>
				<!-- Detail Top Header -->
				<div class="p-4 px-5 border-b border-[#1F1F24] flex flex-col gap-2">
					<div class="flex items-center gap-2">
						<span
							class="px-1.5 py-0.5 rounded-[3px] font-mono text-[10.5px] font-semibold tracking-wider"
							style="background: {act.bg}; color: {act.color};"
						>
							{act.label}
						</span>
						<span class="font-mono text-[11.5px] text-[#6B6B73]">{formatTime(selectedLog.timestamp)}</span>
						<button
							type="button"
							onclick={() => (selectedLog = null)}
							class="ml-auto w-6 h-6 border-none rounded bg-transparent text-[#6B6B73] text-base cursor-pointer hover:bg-[#1B1B20] hover:text-[#E6E6E8] flex items-center justify-center"
						>
							&times;
						</button>
					</div>
					<span class="font-mono text-sm font-medium break-all text-[#E6E6E8]">{selectedLog.host}</span>
					<span class="font-mono text-xs text-[#A3A3AB] break-all leading-relaxed">
						{selectedLog.method} {selectedLog.path}
					</span>
				</div>

				<!-- KV Grid -->
				<div class="p-3.5 px-5 grid grid-cols-[90px_minmax(0,1fr)] row-gap-2.5 gap-x-3 border-b border-[#1F1F24] text-xs">
					<span class="text-[#6B6B73]">User</span>
					<span class="font-mono break-all text-[#E6E6E8]">{selectedLog.username || '—'}</span>

					<span class="text-[#6B6B73]">Client IP</span>
					<span class="font-mono break-all text-[#E6E6E8]">{selectedLog.client_ip}</span>

					<span class="text-[#6B6B73]">Category</span>
					<span class="font-mono break-all text-[#E6E6E8]">{selectedLog.category || 'uncategorized'}</span>

					<span class="text-[#6B6B73]">Matched</span>
					<span class="font-mono break-all text-[#E6E6E8]">
						{#if selectedLog.threat_signals?.some((s) => s.name.includes('dga'))}
							DGA Entropy ({selectedLog.block_reason || 'heuristic'})
						{:else}
							{selectedLog.rule_name || selectedLog.block_reason || '—'}
						{/if}
					</span>

					<span class="text-[#6B6B73]">Status</span>
					<span class="font-mono text-[#E6E6E8]">{selectedLog.status_code}</span>

					<span class="text-[#6B6B73]">Latency</span>
					<span class="font-mono text-[#E6E6E8]">{selectedLog.duration_ms} ms</span>

					<span class="text-[#6B6B73]">TLS</span>
					<span class="font-mono text-[#E6E6E8]">
						{selectedLog.tls_intercepted ? 'intercepted · TLS 1.3' : 'passthrough'}
					</span>

					<span class="text-[#6B6B73]">Node</span>
					<span class="font-mono text-[#E6E6E8]">{selectedLog.node_name || selectedLog.node_id || 'mars-local'}</span>
				</div>

				<!-- Threat Signals Block (if present) -->
				{#if selectedLog.threat_signals && selectedLog.threat_signals.length > 0}
					<div class="p-3.5 px-5 flex flex-col gap-2 border-b border-[#1F1F24]">
						<div class="flex items-center justify-between">
							<span class="font-mono text-[10.5px] font-semibold tracking-[0.12em] uppercase text-[#F87171]">
								Threat signals
							</span>
							<span class="font-mono text-[11px] text-[#A3A3AB]">
								score: {((selectedLog.threat_score ?? 0) * 100).toFixed(0)}% · {selectedLog.threat_tier || 'tier0'}
							</span>
						</div>
						<div class="flex flex-col gap-1.5">
							{#each selectedLog.threat_signals as sig}
								<div class="flex items-center justify-between p-2 px-2.5 rounded bg-[#111113] border border-[#1F1F24] font-mono text-[11px]">
									<span class="text-[#E6E6E8] flex items-center gap-1.5">
										{#if sig.name.includes('dga')}
											<span class="w-1.5 h-1.5 rounded-full bg-[#ED2377]"></span>
										{:else}
											<span class="w-1.5 h-1.5 rounded-full bg-[#FDBA74]"></span>
										{/if}
										{sig.name}
									</span>
									<span class="text-[#6B6B73]">{(sig.score * 100).toFixed(0)}% risk</span>
								</div>
							{/each}
						</div>
					</div>
				{/if}

				<!-- Request Headers Block -->
				<div class="p-3.5 px-5 flex flex-col gap-2">
					<span class="font-mono text-[10.5px] font-semibold tracking-[0.12em] uppercase text-[#55555C]">
						Request headers
					</span>
					<div
						class="p-2.5 px-3 border border-[#1F1F24] rounded-md bg-[#111113] flex flex-col gap-1 font-mono text-[11.5px] leading-relaxed"
					>
						<span class="break-all text-[#C8C8CE]"><span class="text-[#6B6B73]">host: </span>{selectedLog.host}</span>
						<span class="break-all text-[#C8C8CE]"><span class="text-[#6B6B73]">scheme: </span>{selectedLog.scheme}</span>
						<span class="break-all text-[#C8C8CE]"><span class="text-[#6B6B73]">client-ip: </span>{selectedLog.client_ip}</span>
						{#if selectedLog.content_type}
							<span class="break-all text-[#C8C8CE]"><span class="text-[#6B6B73]">content-type: </span>{selectedLog.content_type}</span>
						{/if}
						{#if selectedLog.upstream_addr}
							<span class="break-all text-[#C8C8CE]"><span class="text-[#6B6B73]">upstream: </span>{selectedLog.upstream_addr}</span>
						{/if}
						{#if selectedLog.cache_status}
							<span class="break-all text-[#C8C8CE]"><span class="text-[#6B6B73]">cache-status: </span>{selectedLog.cache_status}</span>
						{/if}
						{#if selectedLog.username}
							<span class="break-all text-[#C8C8CE]"><span class="text-[#6B6B73]">x-conduit-user: </span>{selectedLog.username}</span>
						{/if}
						<span class="break-all text-[#C8C8CE]"><span class="text-[#6B6B73]">x-conduit-node: </span>{selectedLog.node_name || selectedLog.node_id || 'mars-local'}</span>
					</div>
				</div>

				<!-- Footer Quick Actions -->
				<div class="mt-auto p-3.5 px-5 border-t border-[#1F1F24] flex gap-2">
					<button
						type="button"
						onclick={() => blockHost(selectedLog!.host)}
						class="h-7 px-3 border border-[#2A2A30] rounded-md bg-transparent text-[#E6E6E8] text-[12.5px] cursor-pointer hover:bg-[#16161A] transition-colors"
					>
						Block this host
					</button>
					<a
						href="/categories?search={encodeURIComponent(selectedLog.host)}"
						class="h-7 px-3 border border-[#2A2A30] rounded-md bg-transparent text-[#E6E6E8] text-[12.5px] flex items-center justify-center no-underline hover:bg-[#16161A] transition-colors"
					>
						Recategorize
					</a>
				</div>
			</div>
		{/if}
	</div>
</div>
