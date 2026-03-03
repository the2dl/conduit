<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type Stats, type LogEntry, type Health, type NodeStats } from '$lib/api';
	import * as Card from '$lib/components/ui/card';
	import * as Table from '$lib/components/ui/table';
	import { Badge } from '$lib/components/ui/badge';

	let stats = $state<Stats>({ total_requests: 0, blocked_requests: 0, active_connections: 0, tls_intercepted: 0, cache_hits: 0, cache_misses: 0 });
	let health = $state<Health>({ status: 'unknown', dragonfly: false, version: '0.0.0' });
	let recentLogs = $state<LogEntry[]>([]);
	let interval: ReturnType<typeof setInterval>;

	async function refresh() {
		try {
			stats = await api.stats();
			health = await api.health();
			recentLogs = await api.logs({ limit: '10' });
		} catch { /* API may not be up yet */ }
	}

	onMount(() => {
		refresh();
		interval = setInterval(refresh, 3000);
		return () => clearInterval(interval);
	});

	function formatTime(ts: string) {
		return new Date(ts).toLocaleTimeString();
	}
</script>

<div class="mb-6">
	<h2 class="text-2xl font-semibold">Dashboard</h2>
	<p class="text-sm text-muted-foreground mt-1">
		<span class="status-dot {health.status === 'healthy' ? 'status-dot-healthy' : 'status-dot-degraded'} mr-1.5"></span>
		{health.status} &middot; v{health.version}
	</p>
</div>

<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
	<Card.Root>
		<Card.Header class="pb-2">
			<Card.Description class="text-xs uppercase tracking-wide">Total Requests</Card.Description>
		</Card.Header>
		<Card.Content>
			<div class="text-3xl font-bold font-mono text-primary">{stats.total_requests.toLocaleString()}</div>
		</Card.Content>
	</Card.Root>
	<Card.Root>
		<Card.Header class="pb-2">
			<Card.Description class="text-xs uppercase tracking-wide">Blocked</Card.Description>
		</Card.Header>
		<Card.Content>
			<div class="text-3xl font-bold font-mono text-destructive-foreground">{stats.blocked_requests.toLocaleString()}</div>
		</Card.Content>
	</Card.Root>
	<Card.Root>
		<Card.Header class="pb-2">
			<Card.Description class="text-xs uppercase tracking-wide">Active Connections</Card.Description>
		</Card.Header>
		<Card.Content>
			<div class="text-3xl font-bold font-mono text-green-500">{stats.active_connections.toLocaleString()}</div>
		</Card.Content>
	</Card.Root>
	<Card.Root>
		<Card.Header class="pb-2">
			<Card.Description class="text-xs uppercase tracking-wide">TLS Intercepted</Card.Description>
		</Card.Header>
		<Card.Content>
			<div class="text-3xl font-bold font-mono text-yellow-500">{stats.tls_intercepted.toLocaleString()}</div>
		</Card.Content>
	</Card.Root>
</div>

{#if stats.nodes && stats.nodes.length > 0}
	{@const onlineCount = stats.nodes.filter(n => n.online).length}
	<Card.Root class="mb-6">
		<Card.Header class="pb-2">
			<Card.Description class="text-xs uppercase tracking-wide">Proxy Nodes</Card.Description>
		</Card.Header>
		<Card.Content>
			<div class="text-2xl font-bold font-mono">
				<span class="text-green-500">{onlineCount}</span>
				<span class="text-muted-foreground">/ {stats.nodes.length}</span>
				<span class="text-sm font-normal text-muted-foreground ml-2">online</span>
			</div>
		</Card.Content>
	</Card.Root>
{/if}

<Card.Root>
	<Card.Header>
		<Card.Title class="text-sm uppercase tracking-wide text-muted-foreground">Recent Activity</Card.Title>
	</Card.Header>
	<Card.Content>
		{#if recentLogs.length === 0}
			<p class="text-sm text-muted-foreground">No recent activity</p>
		{:else}
			<Table.Root>
				<Table.Header>
					<Table.Row>
						<Table.Head>Time</Table.Head>
						<Table.Head>Action</Table.Head>
						<Table.Head>Method</Table.Head>
						<Table.Head>Host</Table.Head>
						<Table.Head>User</Table.Head>
						<Table.Head>Status</Table.Head>
					</Table.Row>
				</Table.Header>
				<Table.Body>
					{#each recentLogs as log}
						<Table.Row>
							<Table.Cell class="font-mono text-xs">{formatTime(log.timestamp)}</Table.Cell>
							<Table.Cell><span class="badge-{log.action} px-2 py-0.5 rounded text-xs font-semibold uppercase">{log.action}</span></Table.Cell>
							<Table.Cell class="font-mono">{log.method}</Table.Cell>
							<Table.Cell>{log.host}</Table.Cell>
							<Table.Cell>{log.username ?? '-'}</Table.Cell>
							<Table.Cell class="font-mono">{log.status_code}</Table.Cell>
						</Table.Row>
					{/each}
				</Table.Body>
			</Table.Root>
		{/if}
	</Card.Content>
</Card.Root>
