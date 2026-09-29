<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type Stats, type LogEntry, type TimeseriesResponse } from '$lib/api';
	import { drawer } from '$lib/drawer.svelte';

	let stats = $state<Stats>({
		total_requests: 0,
		blocked_requests: 0,
		active_connections: 0,
		tls_intercepted: 0,
		cache_hits: 0,
		cache_misses: 0
	});

	let recentLogs = $state<LogEntry[]>([]);
	let timeseries = $state<TimeseriesResponse | null>(null);
	let selectedRange = $state<'1h' | '24h' | '7d'>('24h');
	let interval: ReturnType<typeof setInterval>;

	interface CountBar {
		name: string;
		count: number;
		formatted: string;
		widthPct: string;
	}

	interface EventItem {
		time: string;
		label: string;
		color: string;
		host: string;
		reason: string;
	}

	interface TimeBar {
		totalHeight: string;
		blockedHeight: string;
	}

	let topCategories = $state<CountBar[]>([]);
	let topHosts = $state<CountBar[]>([]);
	let enforcementEvents = $state<EventItem[]>([]);
	let chartBars = $state<TimeBar[]>([]);

	async function refresh() {
		try {
			const [s, l, ts] = await Promise.all([
				api.stats(),
				api.logs({ limit: '300' }).catch(() => []),
				api.stats.timeseries(selectedRange).catch(() => null)
			]);
			stats = s;
			recentLogs = l;
			timeseries = ts;
			computeDistributions(l, ts);
		} catch {
			/* ignore */
		}
	}

	function onRangeChange(range: '1h' | '24h' | '7d') {
		selectedRange = range;
		refresh();
	}

	function computeDistributions(logs: LogEntry[], ts: TimeseriesResponse | null) {
		// Top Categories from real logs
		const catMap = new Map<string, number>();
		const hostMap = new Map<string, number>();
		const events: EventItem[] = [];

		for (const log of logs) {
			const cat = log.category || 'uncategorized';
			catMap.set(cat, (catMap.get(cat) || 0) + 1);

			if (log.host) {
				hostMap.set(log.host, (hostMap.get(log.host) || 0) + 1);
			}

			if (log.action !== 'allow' || log.status_code >= 400 || log.block_reason) {
				const d = new Date(log.timestamp);
				const timeStr = d.toLocaleTimeString([], {
					hour: '2-digit',
					minute: '2-digit',
					second: '2-digit',
					hour12: false
				});
				const isDlp = log.block_reason?.toLowerCase().includes('dlp');
				events.push({
					time: timeStr,
					label: isDlp ? 'DLP' : log.action.toUpperCase(),
					color: isDlp ? '#FDBA74' : log.action === 'block' ? '#F87171' : '#A3A3AB',
					host: log.host,
					reason: log.rule_name || log.block_reason || `HTTP ${log.status_code}`
				});
			}
		}

		// Sort categories (100% real)
		const sortedCats = Array.from(catMap.entries())
			.sort((a, b) => b[1] - a[1])
			.slice(0, 5);
		const maxCat = sortedCats.length > 0 ? sortedCats[0][1] : 1;
		topCategories = sortedCats.map(([name, count]) => ({
			name,
			count,
			formatted: count.toLocaleString(),
			widthPct: `${Math.max(4, Math.round((count / maxCat) * 100))}%`
		}));

		// Sort hosts (100% real)
		const sortedHosts = Array.from(hostMap.entries())
			.sort((a, b) => b[1] - a[1])
			.slice(0, 5);
		const maxHost = sortedHosts.length > 0 ? sortedHosts[0][1] : 1;
		topHosts = sortedHosts.map(([name, count]) => ({
			name,
			count,
			formatted: count.toLocaleString(),
			widthPct: `${Math.max(4, Math.round((count / maxHost) * 100))}%`
		}));

		// Enforcement events (100% real)
		enforcementEvents = events.slice(0, 5);

		// Real 48 Bars chart from Redis timeseries
		if (ts && ts.buckets && ts.buckets.length > 0) {
			const maxBucket = Math.max(...ts.buckets.map((b) => b.total), 1);
			chartBars = ts.buckets.map((b) => {
				const totalHeight =
					b.total > 0
						? `${Math.max(6, Math.min(100, Math.round((b.total / maxBucket) * 100)))}%`
						: '2px';
				const blockedHeight =
					b.total > 0 && b.blocked > 0 ? `${Math.round((b.blocked / b.total) * 100)}%` : '0%';
				return { totalHeight, blockedHeight };
			});
		} else {
			chartBars = Array.from({ length: 48 }, () => ({
				totalHeight: '2px',
				blockedHeight: '0%'
			}));
		}
	}

	let tlsPct = $derived(
		stats.total_requests > 0
			? `${((stats.tls_intercepted / stats.total_requests) * 100).toFixed(1)}%`
			: '100%'
	);

	let deltaText = $derived.by(() => {
		if (
			timeseries?.prior_period_delta_pct !== null &&
			timeseries?.prior_period_delta_pct !== undefined
		) {
			const d = timeseries.prior_period_delta_pct;
			const sign = d > 0 ? '+' : '';
			return `${sign}${d.toFixed(0)}% vs prior`;
		}
		return 'live throughput';
	});

	let modeEnforcing = $derived(
		drawer.config.prevention_mode === 'true' || drawer.config.prevention_mode === '1'
	);

	let nodeCountLabel = $derived(
		stats.nodes && stats.nodes.length > 0
			? `${stats.nodes.length} node${stats.nodes.length > 1 ? 's' : ''}`
			: '1 node'
	);

	onMount(() => {
		refresh();
		interval = setInterval(refresh, 3000);
		return () => clearInterval(interval);
	});
</script>

<div class="flex-1 flex flex-col h-full overflow-hidden">
	<!-- Page Header with 1h/24h/7d Segmented Control -->
	<header class="h-14 shrink-0 flex items-center gap-3 px-7 border-b border-[#1F1F24]">
		<div class="flex items-center gap-2">
			<span class="text-[15px] font-semibold">Overview</span>
			<span class="w-1.5 h-1.5 rounded-full bg-[#4ADE80]"></span>
		</div>
		<span class="text-[#6B6B73]">real-time proxy activity</span>

		<div class="ml-auto flex items-center p-0.5 border border-[#1F1F24] rounded-md bg-[#111113]">
			<button
				type="button"
				onclick={() => onRangeChange('1h')}
				class="px-2.5 py-1 text-xs cursor-pointer font-medium transition-colors {selectedRange ===
				'1h'
					? 'bg-[#16161A] text-[#E6E6E8] rounded-[4px]'
					: 'text-[#6B6B73] hover:text-[#E6E6E8]'}"
			>
				1h
			</button>
			<button
				type="button"
				onclick={() => onRangeChange('24h')}
				class="px-2.5 py-1 text-xs cursor-pointer font-medium transition-colors {selectedRange ===
				'24h'
					? 'bg-[#16161A] text-[#E6E6E8] rounded-[4px]'
					: 'text-[#6B6B73] hover:text-[#E6E6E8]'}"
			>
				24h
			</button>
			<button
				type="button"
				onclick={() => onRangeChange('7d')}
				class="px-2.5 py-1 text-xs cursor-pointer font-medium transition-colors {selectedRange ===
				'7d'
					? 'bg-[#16161A] text-[#E6E6E8] rounded-[4px]'
					: 'text-[#6B6B73] hover:text-[#E6E6E8]'}"
			>
				7d
			</button>
		</div>
	</header>

	<!-- Content Body -->
	<div class="flex-1 overflow-auto p-7 pb-10 flex flex-col gap-4">
		<!-- 5-Cell Stats Strip -->
		<div
			class="grid grid-cols-5 border border-[#1F1F24] rounded-lg bg-[#111113] overflow-hidden"
		>
			<!-- Requests -->
			<div class="p-4 px-4.5 flex flex-col gap-1.5">
				<span class="text-xs text-[#6B6B73]">Requests</span>
				<span
					class="text-[clamp(18px,1.9vw,24px)] font-medium tracking-tight font-mono text-[#E6E6E8]"
				>
					{stats.total_requests.toLocaleString()}
				</span>
				<span
					class="font-mono text-[11px] text-[#6B6B73] whitespace-nowrap overflow-hidden text-ellipsis"
				>
					{deltaText}
				</span>
			</div>

			<!-- Blocked -->
			<div class="p-4 px-4.5 flex flex-col gap-1.5 border-l border-[#1F1F24]">
				<span class="text-xs text-[#6B6B73]">Blocked</span>
				<span
					class="text-[clamp(18px,1.9vw,24px)] font-medium tracking-tight font-mono text-[#F87171]"
				>
					{stats.blocked_requests.toLocaleString()}
				</span>
				<span
					class="font-mono text-[11px] text-[#6B6B73] whitespace-nowrap overflow-hidden text-ellipsis"
				>
					{modeEnforcing ? 'enforced' : 'logged only'}
				</span>
			</div>

			<!-- DLP Matches -->
			<div class="p-4 px-4.5 flex flex-col gap-1.5 border-l border-[#1F1F24]">
				<span class="text-xs text-[#6B6B73]">DLP matches</span>
				<span
					class="text-[clamp(18px,1.9vw,24px)] font-medium tracking-tight font-mono text-[#FDBA74]"
				>
					{drawer.dlpCount.toLocaleString()}
				</span>
				<span
					class="font-mono text-[11px] text-[#6B6B73] whitespace-nowrap overflow-hidden text-ellipsis"
				>
					{drawer.dlpCount} rule{drawer.dlpCount === 1 ? '' : 's'} active
				</span>
			</div>

			<!-- Connections -->
			<div class="p-4 px-4.5 flex flex-col gap-1.5 border-l border-[#1F1F24]">
				<span class="text-xs text-[#6B6B73]">Connections</span>
				<span
					class="text-[clamp(18px,1.9vw,24px)] font-medium tracking-tight font-mono text-[#E6E6E8]"
				>
					{stats.active_connections.toLocaleString()}
				</span>
				<span
					class="font-mono text-[11px] text-[#6B6B73] whitespace-nowrap overflow-hidden text-ellipsis"
				>
					{nodeCountLabel}
				</span>
			</div>

			<!-- TLS Intercepted -->
			<div class="p-4 px-4.5 flex flex-col gap-1.5 border-l border-[#1F1F24]">
				<span class="text-xs text-[#6B6B73]">TLS intercepted</span>
				<span
					class="text-[clamp(18px,1.9vw,24px)] font-medium tracking-tight font-mono text-[#E6E6E8]"
				>
					{tlsPct}
				</span>
				<span
					class="font-mono text-[11px] text-[#6B6B73] whitespace-nowrap overflow-hidden text-ellipsis"
				>
					{stats.tls_intercepted.toLocaleString()} inspected
				</span>
			</div>
		</div>

		<!-- Requests 48-Bar Chart Card (Real Timeseries) -->
		<div
			class="border border-[#1F1F24] rounded-lg bg-[#111113] p-4 px-4.5 flex flex-col gap-3.5"
		>
			<div class="flex items-center gap-4">
				<span class="font-semibold text-[13px]">Requests</span>
				{#if timeseries}
					<span class="font-mono text-xs text-[#A3A3AB]">
						{timeseries.total_in_range.toLocaleString()} requests in {selectedRange}
					</span>
				{/if}
				<div class="ml-auto flex items-center gap-4">
					<span class="flex items-center gap-1.5 text-[#6B6B73] text-xs">
						<span class="w-2 h-2 rounded-[2px] bg-[#3A3A42]"></span>
						allowed
					</span>
					<span class="flex items-center gap-1.5 text-[#6B6B73] text-xs">
						<span class="w-2 h-2 rounded-[2px] bg-[#ED2377]"></span>
						blocked
					</span>
				</div>
			</div>
			<div class="h-[140px] flex items-end gap-[3px]">
				{#each chartBars as bar}
					<div
						class="flex-1 flex flex-col gap-px rounded-t-[2px] overflow-hidden"
						style="height: {bar.totalHeight};"
					>
						{#if bar.blockedHeight !== '0%'}
							<div style="height: {bar.blockedHeight}; background: #ED2377;"></div>
						{/if}
						<div class="flex-1 bg-[#2E2E35]"></div>
					</div>
				{/each}
			</div>
			<div class="flex justify-between font-mono text-[11px] text-[#55555C]">
				<span>{selectedRange === '1h' ? '-1h' : selectedRange === '7d' ? '-7d' : '-24h'}</span>
				<span>{selectedRange === '1h' ? '-45m' : selectedRange === '7d' ? '-5d' : '-18h'}</span>
				<span>{selectedRange === '1h' ? '-30m' : selectedRange === '7d' ? '-3d' : '-12h'}</span>
				<span>{selectedRange === '1h' ? '-15m' : selectedRange === '7d' ? '-1d' : '-6h'}</span>
				<span>now</span>
			</div>
		</div>

		<!-- 3-Card Responsive Grid -->
		<div class="grid grid-cols-[repeat(auto-fit,minmax(260px,1fr))] gap-4">
			<!-- Top Categories -->
			<div
				class="border border-[#1F1F24] rounded-lg bg-[#111113] p-4 px-4.5 flex flex-col gap-3 min-h-[140px]"
			>
				<span class="font-semibold text-[13px]">Top categories</span>
				{#if topCategories.length === 0}
					<div class="flex-1 flex items-center justify-center font-mono text-xs text-[#6B6B73]">
						No categorized traffic yet
					</div>
				{:else}
					<div class="flex flex-col gap-3">
						{#each topCategories as cat}
							<div class="flex flex-col gap-1.5">
								<div class="flex justify-between font-mono text-xs">
									<span class="text-[#C8C8CE]">{cat.name}</span>
									<span class="text-[#6B6B73]">{cat.formatted}</span>
								</div>
								<div class="h-[3px] rounded-full bg-[#1B1B20]">
									<div
										class="h-[3px] rounded-full bg-[#55555C]"
										style="width: {cat.widthPct};"
									></div>
								</div>
							</div>
						{/each}
					</div>
				{/if}
			</div>

			<!-- Top Hosts -->
			<div
				class="border border-[#1F1F24] rounded-lg bg-[#111113] p-4 px-4.5 flex flex-col gap-3 min-h-[140px]"
			>
				<span class="font-semibold text-[13px]">Top hosts</span>
				{#if topHosts.length === 0}
					<div class="flex-1 flex items-center justify-center font-mono text-xs text-[#6B6B73]">
						No host traffic yet
					</div>
				{:else}
					<div class="flex flex-col gap-3">
						{#each topHosts as host}
							<div class="flex flex-col gap-1.5">
								<div class="flex justify-between gap-3 font-mono text-xs">
									<span class="text-[#C8C8CE] truncate">{host.name}</span>
									<span class="text-[#6B6B73] shrink-0">{host.formatted}</span>
								</div>
								<div class="h-[3px] rounded-full bg-[#1B1B20]">
									<div
										class="h-[3px] rounded-full bg-[#55555C]"
										style="width: {host.widthPct};"
									></div>
								</div>
							</div>
						{/each}
					</div>
				{/if}
			</div>

			<!-- Enforcement Events -->
			<div
				class="border border-[#1F1F24] rounded-lg bg-[#111113] p-4 px-4.5 flex flex-col gap-1 min-h-[140px]"
			>
				<div class="flex items-center mb-2">
					<span class="font-semibold text-[13px]">Enforcement events</span>
					<a
						href="/traffic"
						class="ml-auto text-xs text-[#A3A3AB] hover:text-[#E6E6E8] no-underline transition-colors"
					>
						View in traffic &rarr;
					</a>
				</div>
				{#if enforcementEvents.length === 0}
					<div
						class="flex-1 flex flex-col items-center justify-center gap-1.5 font-mono text-xs text-[#6B6B73]"
					>
						<div class="flex items-center gap-2">
							<span class="w-1.5 h-1.5 rounded-full bg-[#4ADE80]"></span>
							<span>All traffic allowed</span>
						</div>
						<span class="text-[11px] text-[#55555C]">No block or DLP triggers recorded</span>
					</div>
				{:else}
					{#each enforcementEvents as event}
						<div
							class="grid grid-cols-[58px_48px_minmax(0,1fr)] gap-2.5 items-center h-7 text-xs border-b border-[#151518] last:border-none"
						>
							<span class="font-mono text-[#6B6B73]">{event.time}</span>
							<span
								class="flex items-center gap-1.5 font-mono text-[10.5px] font-semibold tracking-wider"
								style="color: {event.color};"
							>
								<span
									class="w-[5px] h-[5px] rounded-full"
									style="background: {event.color};"
								></span>
								{event.label}
							</span>
							<div class="flex gap-2 min-w-0">
								<span class="font-mono truncate text-[#E6E6E8]">{event.host}</span>
								<span class="truncate text-[#6B6B73]">{event.reason}</span>
							</div>
						</div>
					{/each}
				{/if}
			</div>
		</div>
	</div>
</div>
