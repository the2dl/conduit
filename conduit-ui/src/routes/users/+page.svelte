<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type LogEntry } from '$lib/api';
	import * as Card from '$lib/components/ui/card';
	import * as Table from '$lib/components/ui/table';

	interface UserSummary {
		username: string;
		requests: number;
		blocked: number;
		lastSeen: string;
		topDomains: string[];
	}

	let users = $state<UserSummary[]>([]);
	let loading = $state(true);

	async function load() {
		loading = true;
		try {
			const logs = await api.logs({ limit: '5000' });
			const userMap = new Map<string, { requests: number; blocked: number; lastSeen: string; domains: Map<string, number> }>();

			for (const log of logs) {
				const name = log.username ?? log.client_ip;
				if (!userMap.has(name)) {
					userMap.set(name, { requests: 0, blocked: 0, lastSeen: log.timestamp, domains: new Map() });
				}
				const u = userMap.get(name)!;
				u.requests++;
				if (log.action === 'block') u.blocked++;
				if (log.timestamp > u.lastSeen) u.lastSeen = log.timestamp;
				u.domains.set(log.host, (u.domains.get(log.host) ?? 0) + 1);
			}

			users = Array.from(userMap.entries()).map(([username, data]) => ({
				username,
				requests: data.requests,
				blocked: data.blocked,
				lastSeen: data.lastSeen,
				topDomains: Array.from(data.domains.entries())
					.sort((a, b) => b[1] - a[1])
					.slice(0, 3)
					.map(([d]) => d)
			})).sort((a, b) => b.requests - a.requests);
		} catch { /* ignore */ }
		loading = false;
	}

	function formatTs(ts: string) {
		return new Date(ts).toLocaleString();
	}

	onMount(load);
</script>

<div class="mb-6">
	<h2 class="text-2xl font-semibold">Users</h2>
	<p class="text-sm text-muted-foreground mt-1">User activity overview (aggregated from recent logs)</p>
</div>

<Card.Root class="overflow-x-auto">
	<Card.Content class="pt-6">
		{#if loading}
			<p class="text-sm text-muted-foreground">Loading...</p>
		{:else if users.length === 0}
			<p class="text-sm text-muted-foreground">No user activity found</p>
		{:else}
			<Table.Root>
				<Table.Header>
					<Table.Row>
						<Table.Head>User / IP</Table.Head>
						<Table.Head>Requests</Table.Head>
						<Table.Head>Blocked</Table.Head>
						<Table.Head>Last Seen</Table.Head>
						<Table.Head>Top Domains</Table.Head>
					</Table.Row>
				</Table.Header>
				<Table.Body>
					{#each users as user}
						<Table.Row>
							<Table.Cell class="font-mono">{user.username}</Table.Cell>
							<Table.Cell class="font-mono">{user.requests}</Table.Cell>
							<Table.Cell class="font-mono {user.blocked > 0 ? 'text-destructive-foreground' : ''}">{user.blocked}</Table.Cell>
							<Table.Cell class="whitespace-nowrap">{formatTs(user.lastSeen)}</Table.Cell>
							<Table.Cell>{user.topDomains.join(', ')}</Table.Cell>
						</Table.Row>
					{/each}
				</Table.Body>
			</Table.Root>
		{/if}
	</Card.Content>
</Card.Root>
