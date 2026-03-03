<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type LogEntry } from '$lib/api';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import * as Card from '$lib/components/ui/card';
	import * as Table from '$lib/components/ui/table';
	import * as Select from '$lib/components/ui/select';

	let logs = $state<LogEntry[]>([]);
	let domainFilter = $state('');
	let userFilter = $state('');
	let actionFilter = $state('');
	let loading = $state(false);

	async function fetchLogs() {
		loading = true;
		try {
			const params: Record<string, string> = { limit: '200' };
			if (domainFilter) params.domain = domainFilter;
			if (userFilter) params.user = userFilter;
			if (actionFilter) params.action = actionFilter;
			logs = await api.logs(params);
		} catch { /* ignore */ }
		loading = false;
	}

	function exportCsv() {
		const params = new URLSearchParams({ format: 'csv' });
		if (domainFilter) params.set('domain', domainFilter);
		if (userFilter) params.set('user', userFilter);
		window.open(`/api/v1/export/logs?${params}`, '_blank');
	}

	onMount(fetchLogs);

	function formatTs(ts: string) {
		const d = new Date(ts);
		return d.toLocaleString();
	}

	function onActionChange(val: string | undefined) {
		actionFilter = val ?? '';
		fetchLogs();
	}
</script>

<div class="mb-6">
	<h2 class="text-2xl font-semibold">Logs</h2>
	<p class="text-sm text-muted-foreground mt-1">Searchable request log viewer</p>
</div>

<div class="flex flex-wrap items-center gap-3 mb-4">
	<Input type="text" placeholder="Filter by domain..." bind:value={domainFilter} onkeydown={(e) => e.key === 'Enter' && fetchLogs()} class="flex-1 min-w-[200px]" />
	<Input type="text" placeholder="Filter by user..." bind:value={userFilter} onkeydown={(e) => e.key === 'Enter' && fetchLogs()} class="min-w-[160px]" />
	<Select.Root type="single" value={actionFilter} onValueChange={onActionChange}>
		<Select.Trigger class="w-[140px]">
			{actionFilter || 'All actions'}
		</Select.Trigger>
		<Select.Content>
			<Select.Item value="" label="All actions" />
			<Select.Item value="allow" label="Allow" />
			<Select.Item value="block" label="Block" />
			<Select.Item value="log" label="Log" />
		</Select.Content>
	</Select.Root>
	<Button onclick={fetchLogs}>Search</Button>
	<Button variant="outline" onclick={exportCsv}>Export CSV</Button>
</div>

<Card.Root class="overflow-x-auto">
	<Card.Content class="pt-6">
		{#if loading}
			<p class="text-sm text-muted-foreground">Loading...</p>
		{:else if logs.length === 0}
			<p class="text-sm text-muted-foreground">No logs found</p>
		{:else}
			<Table.Root>
				<Table.Header>
					<Table.Row>
						<Table.Head>Timestamp</Table.Head>
						<Table.Head>Action</Table.Head>
						<Table.Head>Method</Table.Head>
						<Table.Head>Host</Table.Head>
						<Table.Head>Path</Table.Head>
						<Table.Head>User</Table.Head>
						<Table.Head>Category</Table.Head>
						<Table.Head>Status</Table.Head>
						<Table.Head>Duration</Table.Head>
						<Table.Head>TLS</Table.Head>
						<Table.Head>Node</Table.Head>
					</Table.Row>
				</Table.Header>
				<Table.Body>
					{#each logs as log}
						<Table.Row>
							<Table.Cell class="whitespace-nowrap font-mono text-xs">{formatTs(log.timestamp)}</Table.Cell>
							<Table.Cell><span class="badge-{log.action} px-2 py-0.5 rounded text-xs font-semibold uppercase">{log.action}</span></Table.Cell>
							<Table.Cell class="font-mono">{log.method}</Table.Cell>
							<Table.Cell>{log.host}</Table.Cell>
							<Table.Cell class="max-w-[200px] overflow-hidden text-ellipsis">{log.path}</Table.Cell>
							<Table.Cell>{log.username ?? '-'}</Table.Cell>
							<Table.Cell>{log.category ?? '-'}</Table.Cell>
							<Table.Cell class="font-mono">{log.status_code}</Table.Cell>
							<Table.Cell class="font-mono">{log.duration_ms}ms</Table.Cell>
							<Table.Cell>{log.tls_intercepted ? 'Yes' : '-'}</Table.Cell>
							<Table.Cell class="text-xs">{log.node_name ?? '-'}</Table.Cell>
						</Table.Row>
					{/each}
				</Table.Body>
			</Table.Root>
		{/if}
	</Card.Content>
</Card.Root>
