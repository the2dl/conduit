<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type LogEntry } from '$lib/api';

	interface UserRow {
		name: string;
		ip: string;
		initials: string;
		requests: number;
		blocked: number;
		dlp: number;
		lastSeen: string;
		topHosts: string[];
	}

	let users = $state<UserRow[]>([]);
	let loading = $state(true);

	async function loadUsers() {
		loading = true;
		try {
			const logs = await api.logs({ limit: '2000' });
			const map = new Map<string, {
				ip: string;
				requests: number;
				blocked: number;
				dlp: number;
				lastSeen: string;
				hosts: Map<string, number>;
			}>();

			for (const log of logs) {
				const username = log.username || log.client_ip;
				if (!map.has(username)) {
					map.set(username, {
						ip: log.client_ip,
						requests: 0,
						blocked: 0,
						dlp: 0,
						lastSeen: log.timestamp,
						hosts: new Map()
					});
				}
				const u = map.get(username)!;
				u.requests++;
				const isDlp = log.block_reason?.toLowerCase().includes('dlp');
				if (isDlp) u.dlp++;
				else if (log.action === 'block') u.blocked++;

				if (log.timestamp > u.lastSeen) u.lastSeen = log.timestamp;
				if (log.host) {
					u.hosts.set(log.host, (u.hosts.get(log.host) || 0) + 1);
				}
			}

			const list = Array.from(map.entries()).map(([name, data]) => {
				const top = Array.from(data.hosts.entries())
					.sort((a, b) => b[1] - a[1])
					.slice(0, 3)
					.map(([h]) => h);
				const initials = name.slice(0, 2).toUpperCase();
				const seenDate = new Date(data.lastSeen);
				const now = new Date();
				const diffMin = Math.round((now.getTime() - seenDate.getTime()) / 60000);
				const seenStr = diffMin < 1 ? 'just now' : diffMin < 60 ? `${diffMin}m ago` : `${Math.round(diffMin / 60)}h ago`;

				return {
					name,
					ip: data.ip,
					initials,
					requests: data.requests,
					blocked: data.blocked,
					dlp: data.dlp,
					lastSeen: seenStr,
					topHosts: top
				};
			}).sort((a, b) => b.requests - a.requests);

			users = list;
		} catch {
			/* ignore */
		}
		loading = false;
	}

	onMount(loadUsers);
</script>

<div class="flex-1 flex flex-col h-full overflow-hidden">
	<!-- Page Header -->
	<header class="h-14 shrink-0 flex items-center gap-3 px-7 border-b border-[#1F1F24]">
		<span class="text-[15px] font-semibold">Users</span>
		<span class="text-[#6B6B73]">aggregated from the last 24h of traffic</span>
	</header>

	<!-- Table Area -->
	<div class="flex-1 overflow-auto">
		<div
			class="grid grid-cols-[minmax(160px,1fr)_90px_80px_80px_100px_minmax(240px,2fr)] gap-4 items-center h-8 px-7 border-b border-[#1F1F24] font-mono text-[10.5px] tracking-wider uppercase text-[#55555C] sticky top-0 bg-[#0A0A0B] z-10"
		>
			<span>User</span>
			<span class="text-right">Requests</span>
			<span class="text-right">Blocked</span>
			<span class="text-right">DLP</span>
			<span>Last seen</span>
			<span>Top hosts</span>
		</div>

		{#if loading}
			<div class="p-12 px-7 text-[#6B6B73]">Loading users...</div>
		{:else if users.length === 0}
			<div class="p-12 px-7 text-[#6B6B73]">No user traffic recorded yet.</div>
		{:else}
			{#each users as u}
				<div
					class="grid grid-cols-[minmax(160px,1fr)_90px_80px_80px_100px_minmax(240px,2fr)] gap-4 items-center h-12 px-7 border-b border-[#151518] font-mono text-xs hover:bg-[#131316] transition-colors"
				>
					<!-- User cell -->
					<div class="flex items-center gap-2.5 min-w-0">
						<span
							class="w-6 h-6 shrink-0 rounded-[5px] bg-[#1B1B20] flex items-center justify-center text-[10.5px] text-[#A3A3AB]"
						>
							{u.initials}
						</span>
						<div class="flex flex-col min-w-0">
							<span class="font-sans text-[13px] font-medium text-[#E6E6E8] truncate">{u.name}</span>
							<span class="text-[11px] text-[#6B6B73] font-mono truncate">{u.ip}</span>
						</div>
					</div>

					<!-- Requests -->
					<span class="text-right text-[#E6E6E8]">{u.requests.toLocaleString()}</span>

					<!-- Blocked -->
					<span class="text-right {u.blocked > 0 ? 'text-[#F87171]' : 'text-[#55555C]'}">
						{u.blocked}
					</span>

					<!-- DLP -->
					<span class="text-right {u.dlp > 0 ? 'text-[#FDBA74]' : 'text-[#55555C]'}">
						{u.dlp}
					</span>

					<!-- Last seen -->
					<span class="text-[#A3A3AB]">{u.lastSeen}</span>

					<!-- Top hosts chips -->
					<div class="flex flex-wrap gap-1">
						{#each u.topHosts as host}
							<span
								class="px-1.5 py-px rounded-[3px] bg-[#16161A] border border-[#1F1F24] text-[11px] text-[#A3A3AB]"
							>
								{host}
							</span>
						{/each}
					</div>
				</div>
			{/each}
		{/if}
	</div>
</div>
