<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type NodeInfo } from '$lib/api';
	import { showToast } from '$lib/toast.svelte';

	let nodes = $state<NodeInfo[]>([]);
	let joinToken = $state('');
	let generatingToken = $state(false);
	let loading = $state(true);

	async function loadNodes() {
		try {
			nodes = await api.nodes.list();
		} catch {
			/* ignore */
		}
		loading = false;
	}

	function formatUptime(node: NodeInfo): string {
		if (node.registration.status === 'pending') return 'pending';
		if (!node.online) return 'offline';
		const secs = node.heartbeat?.uptime_secs;
		if (secs === undefined || secs === null) return 'just started';
		if (secs < 60) return `${secs}s`;
		if (secs < 3600) return `${Math.floor(secs / 60)}m`;
		const h = Math.floor(secs / 3600);
		const d = Math.floor(h / 24);
		if (d > 0) return `${d}d ${h % 24}h`;
		return `${h}h ${Math.floor((secs % 3600) / 60)}m`;
	}

	function copyJoin() {
		if (!joinToken) {
			showToast('Click "generate token" below first');
			return;
		}
		const cmd = `conduit join --server localhost:8443 --token ${joinToken}`;
		navigator.clipboard?.writeText(cmd);
		showToast('Copied join command');
	}

	async function rotateToken() {
		generatingToken = true;
		try {
			const name = `node-${Math.random().toString(16).slice(2, 8)}`;
			const res = await api.nodes.create(name);
			joinToken = res.enrollment_token;
			showToast('New join token generated');
			await loadNodes();
		} catch {
			showToast('Failed to generate token');
		} finally {
			generatingToken = false;
		}
	}

	async function deleteNode(id: string) {
		try {
			await api.nodes.remove(id);
			showToast('Node removed');
			await loadNodes();
		} catch {
			showToast('Failed to remove node');
		}
	}

	let subtitle = $derived(
		nodes.length <= 1 ? 'single-node deployment' : `${nodes.length}-node cluster`
	);

	onMount(() => {
		loadNodes();
		const interval = setInterval(loadNodes, 5000);
		return () => clearInterval(interval);
	});
</script>

<div class="flex-1 flex flex-col h-full overflow-hidden">
	<!-- Page Header -->
	<header class="h-14 shrink-0 flex items-center gap-3 px-7 border-b border-[#1F1F24]">
		<span class="text-[15px] font-semibold">Nodes</span>
		<span class="text-[#6B6B73]">{subtitle}</span>
	</header>

	<!-- Content Area -->
	<div class="flex-1 overflow-auto p-5 px-7 pb-10 flex flex-col gap-4">
		{#if loading}
			<div class="p-8 text-[#6B6B73]">Loading nodes...</div>
		{:else if nodes.length === 0}
			<!-- Fallback single primary node card if none registered -->
			<div
				class="border border-[#1F1F24] rounded-lg bg-[#111113] grid grid-cols-[minmax(200px,1.4fr)_repeat(4,minmax(0,1fr))] items-center p-3.5 px-4.5 gap-4"
			>
				<div class="flex flex-col gap-0.5">
					<div class="flex items-center gap-2 font-medium">
						<span class="w-1.5 h-1.5 rounded-full bg-[#4ADE80]"></span>
						<span class="text-[#E6E6E8]">conduit-01</span>
						<span class="px-1.5 rounded-[3px] bg-[#1B1B20] font-mono text-[10.5px] text-[#A3A3AB]">
							primary
						</span>
					</div>
					<span class="font-mono text-[11.5px] text-[#6B6B73]">localhost:8443</span>
				</div>
				<div class="flex flex-col gap-0.5">
					<span class="text-[11.5px] text-[#6B6B73]">Uptime</span>
					<span class="font-mono text-[#E6E6E8]">active</span>
				</div>
				<div class="flex flex-col gap-0.5">
					<span class="text-[11.5px] text-[#6B6B73]">Connections</span>
					<span class="font-mono text-[#E6E6E8]">1</span>
				</div>
				<div class="flex flex-col gap-0.5">
					<span class="text-[11.5px] text-[#6B6B73]">Dragonfly</span>
					<span class="font-mono text-[#4ADE80]">connected</span>
				</div>
				<div class="flex flex-col gap-0.5">
					<span class="text-[11.5px] text-[#6B6B73]">Version</span>
					<span class="font-mono text-[#E6E6E8]">0.1.0</span>
				</div>
			</div>
		{:else}
			{#each nodes as node, idx}
				{@const isOnline = node.online}
				{@const isPending = node.registration.status === 'pending'}
				<div
					class="border border-[#1F1F24] rounded-lg bg-[#111113] grid grid-cols-[minmax(200px,1.4fr)_repeat(4,minmax(0,1fr))_32px] items-center p-3.5 px-4.5 gap-4"
				>
					<div class="flex flex-col gap-0.5">
						<div class="flex items-center gap-2 font-medium">
							<span
								class="w-1.5 h-1.5 rounded-full {isOnline
									? 'bg-[#4ADE80]'
									: isPending
										? 'bg-[#FACC15]'
										: 'bg-[#F87171]'}"
							></span>
							<span class="text-[#E6E6E8]">{node.name || node.id}</span>
							{#if isPending}
								<span
									class="px-1.5 rounded-[3px] bg-[#2A2410] border border-[#4A3D15] font-mono text-[10px] text-[#FACC15]"
								>
									pending
								</span>
							{:else if idx === 0}
								<span
									class="px-1.5 rounded-[3px] bg-[#1B1B20] font-mono text-[10.5px] text-[#A3A3AB]"
								>
									primary
								</span>
							{/if}
						</div>
						<span class="font-mono text-[11.5px] text-[#6B6B73]">
							{node.heartbeat?.listen_addr || 'localhost:8443'}
						</span>
					</div>

					<div class="flex flex-col gap-0.5">
						<span class="text-[11.5px] text-[#6B6B73]">Uptime</span>
						<span class="font-mono text-[#E6E6E8]">
							{formatUptime(node)}
						</span>
					</div>

					<div class="flex flex-col gap-0.5">
						<span class="text-[11.5px] text-[#6B6B73]">Connections</span>
						<span class="font-mono text-[#E6E6E8]">
							{node.heartbeat?.active_connections ?? 0}
						</span>
					</div>

					<div class="flex flex-col gap-0.5">
						<span class="text-[11.5px] text-[#6B6B73]">Dragonfly</span>
						<span
							class="font-mono {isOnline ? 'text-[#4ADE80]' : 'text-[#6B6B73]'}"
						>
							{isOnline ? 'connected' : 'waiting'}
						</span>
					</div>

					<div class="flex flex-col gap-0.5">
						<span class="text-[11.5px] text-[#6B6B73]">Version</span>
						<span class="font-mono text-[#E6E6E8]">
							{node.heartbeat?.version || '0.1.0'}
						</span>
					</div>

					<button
						type="button"
						aria-label="Remove node"
						onclick={() => deleteNode(node.id)}
						title="Remove node"
						class="w-7 h-7 flex items-center justify-center rounded text-[#6B6B73] hover:text-[#F87171] hover:bg-[#1E1214] transition-colors border-none bg-transparent cursor-pointer"
					>
						<svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
							<path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2M10 11v6M14 11v6"/>
						</svg>
					</button>
				</div>
			{/each}
		{/if}

		<!-- Add a node Dashed Card -->
		<div
			class="border border-dashed border-[#2A2A30] rounded-lg p-5.5 px-6 flex flex-col gap-3.5 max-w-[760px]"
		>
			<div class="flex flex-col gap-1">
				<span class="text-sm font-semibold text-[#E6E6E8]">Add a node</span>
				<span class="text-[#6B6B73] leading-relaxed">
					Run this on the new host to join this deployment, pull policies and categories, and proxy traffic.
				</span>
			</div>
			{#if joinToken}
				<div
					class="flex items-center gap-2.5 p-2.5 px-3 border border-[#1F1F24] rounded-md bg-[#0A0A0B] font-mono text-xs"
				>
					<span class="text-[#55555C]">$</span>
					<span class="flex-1 break-all text-[#E6E6E8]">
						conduit join --server localhost:8443 --token {joinToken}
					</span>
					<button
						type="button"
						onclick={copyJoin}
						class="h-6 px-2.5 border border-[#2A2A30] rounded bg-transparent text-[#A3A3AB] text-[11.5px] cursor-pointer hover:text-[#E6E6E8] hover:bg-[#16161A] transition-colors"
					>
						Copy
					</button>
				</div>
				<div class="flex gap-1.5 font-mono text-[11px] text-[#55555C]">
					<span>token expires in 24h &middot;</span>
					<button
						type="button"
						onclick={rotateToken}
						disabled={generatingToken}
						class="border-none bg-transparent p-0 text-[#A3A3AB] font-inherit text-inherit cursor-pointer hover:text-[#E6E6E8] underline"
					>
						{generatingToken ? 'generating...' : 'rotate token'}
					</button>
				</div>
			{:else}
				<div>
					<button
						type="button"
						onclick={rotateToken}
						disabled={generatingToken}
						class="h-7 px-3 border border-[#2A2A30] rounded bg-[#16161A] text-[#E6E6E8] text-xs font-medium cursor-pointer hover:border-[#ED2377] transition-colors"
					>
						{generatingToken ? 'Generating...' : 'Generate Join Token'}
					</button>
				</div>
			{/if}
		</div>
	</div>
</div>
