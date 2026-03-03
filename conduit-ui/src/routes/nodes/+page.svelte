<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type NodeInfo, type NodeEnrollment } from '$lib/api';
	import * as Card from '$lib/components/ui/card';
	import * as Table from '$lib/components/ui/table';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';

	let nodes = $state<NodeInfo[]>([]);
	let showAddForm = $state(false);
	let newNodeName = $state('');
	let enrollment = $state<NodeEnrollment | null>(null);
	let confirmDelete = $state<string | null>(null);
	let copied = $state(false);
	let interval: ReturnType<typeof setInterval>;

	async function refresh() {
		try {
			nodes = await api.nodes.list();
		} catch { /* API may not be up yet */ }
	}

	onMount(() => {
		refresh();
		interval = setInterval(refresh, 5000);
		return () => clearInterval(interval);
	});

	async function addNode() {
		if (!newNodeName.trim()) return;
		try {
			enrollment = await api.nodes.create(newNodeName.trim());
			showAddForm = false;
			newNodeName = '';
			await refresh();
		} catch (e) {
			alert(`Failed to create node: ${e}`);
		}
	}

	async function deleteNode(id: string) {
		try {
			await api.nodes.remove(id);
			confirmDelete = null;
			await refresh();
		} catch (e) {
			alert(`Failed to delete node: ${e}`);
		}
	}

	function copyToClipboard(text: string) {
		navigator.clipboard.writeText(text);
		copied = true;
		setTimeout(() => (copied = false), 2000);
	}

	function formatUptime(secs: number): string {
		if (secs < 60) return `${secs}s`;
		if (secs < 3600) return `${Math.floor(secs / 60)}m`;
		if (secs < 86400) return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
		return `${Math.floor(secs / 86400)}d ${Math.floor((secs % 86400) / 3600)}h`;
	}

	function formatTime(ts: string) {
		return new Date(ts).toLocaleString();
	}

	function statusColor(status: string, online: boolean): string {
		if (online) return 'bg-green-500/15 text-green-500';
		if (status === 'pending') return 'bg-yellow-500/15 text-yellow-500';
		return 'bg-red-500/15 text-red-500';
	}

	function handleSubmit(e: SubmitEvent) {
		e.preventDefault();
		addNode();
	}
</script>

<div class="mb-6 flex items-center justify-between">
	<div>
		<h2 class="text-2xl font-semibold">Nodes</h2>
		<p class="text-sm text-muted-foreground mt-1">Manage proxy nodes in your deployment</p>
	</div>
	<Button onclick={() => (showAddForm = true)}>Add Node</Button>
</div>

{#if showAddForm}
	<Card.Root class="mb-6">
		<Card.Header>
			<Card.Title class="text-sm">Add New Node</Card.Title>
		</Card.Header>
		<Card.Content>
			<form onsubmit={handleSubmit} class="flex gap-3">
				<Input bind:value={newNodeName} placeholder="Node name (e.g. proxy-east-1)" class="max-w-xs" />
				<Button type="submit">Create</Button>
				<Button variant="outline" onclick={() => (showAddForm = false)}>Cancel</Button>
			</form>
		</Card.Content>
	</Card.Root>
{/if}

{#if enrollment}
	<Card.Root class="mb-6 border-yellow-500/50">
		<Card.Header>
			<Card.Title class="text-sm text-yellow-500">Node Enrollment Credentials</Card.Title>
			<Card.Description>These credentials are shown only once. Copy them now.</Card.Description>
		</Card.Header>
		<Card.Content>
			<div class="space-y-2 font-mono text-sm">
				<div><span class="text-muted-foreground">Node ID:</span> {enrollment.node_id}</div>
				<div><span class="text-muted-foreground">Dragonfly URL:</span> {enrollment.dragonfly_url}</div>
				<div><span class="text-muted-foreground">User:</span> {enrollment.dragonfly_user}</div>
				<div><span class="text-muted-foreground">Password:</span> {enrollment.dragonfly_password}</div>
				<div><span class="text-muted-foreground">Enrollment Token:</span> {enrollment.enrollment_token}</div>
				<div><span class="text-muted-foreground">HMAC Key:</span> {enrollment.hmac_key}</div>
			</div>
			<div class="mt-4 flex gap-2">
				<Button
					variant="outline"
					size="sm"
					onclick={() => copyToClipboard(`[node]\nnode_id = "${enrollment?.node_id}"\ndragonfly_url = "${enrollment?.dragonfly_url}"\nname = "${enrollment?.node_id}"\nenrollment_token = "${enrollment?.enrollment_token}"\nhmac_key = "${enrollment?.hmac_key}"`)}
				>
					{copied ? 'Copied!' : 'Copy TOML Config'}
				</Button>
				<Button variant="ghost" size="sm" onclick={() => (enrollment = null)}>Dismiss</Button>
			</div>
		</Card.Content>
	</Card.Root>
{/if}

<Card.Root>
	<Card.Content class="pt-6">
		{#if nodes.length === 0}
			<p class="text-sm text-muted-foreground text-center py-8">
				No proxy nodes registered. Add a node to get started with multi-node deployment.
			</p>
		{:else}
			<Table.Root>
				<Table.Header>
					<Table.Row>
						<Table.Head>Name</Table.Head>
						<Table.Head>Node ID</Table.Head>
						<Table.Head>Status</Table.Head>
						<Table.Head>Verified</Table.Head>
						<Table.Head>Version</Table.Head>
						<Table.Head>Connections</Table.Head>
						<Table.Head>Uptime</Table.Head>
						<Table.Head>Last Seen</Table.Head>
						<Table.Head></Table.Head>
					</Table.Row>
				</Table.Header>
				<Table.Body>
					{#each nodes as node}
						<Table.Row>
							<Table.Cell class="font-medium">{node.name}</Table.Cell>
							<Table.Cell class="font-mono text-xs">{node.id}</Table.Cell>
							<Table.Cell>
								<span class="px-2 py-0.5 rounded text-xs font-semibold uppercase {statusColor(node.status, node.online)}">
									{node.online ? 'online' : 'offline'}
								</span>
							</Table.Cell>
							<Table.Cell>
								{#if !node.online}
									<span class="text-muted-foreground">-</span>
								{:else if node.heartbeat_verified}
									<span class="text-green-500 text-xs font-semibold">HMAC OK</span>
								{:else}
									<span class="text-red-400 text-xs font-semibold">UNSIGNED</span>
								{/if}
							</Table.Cell>
							<Table.Cell class="font-mono text-xs">{node.heartbeat?.version ?? '-'}</Table.Cell>
							<Table.Cell class="font-mono">{node.heartbeat?.active_connections ?? '-'}</Table.Cell>
							<Table.Cell>{node.heartbeat ? formatUptime(node.heartbeat.uptime_secs) : '-'}</Table.Cell>
							<Table.Cell class="text-xs">{node.heartbeat ? formatTime(node.heartbeat.timestamp) : '-'}</Table.Cell>
							<Table.Cell>
								{#if confirmDelete === node.id}
									<div class="flex gap-1">
										<Button variant="destructive" size="sm" onclick={() => deleteNode(node.id)}>Confirm</Button>
										<Button variant="ghost" size="sm" onclick={() => (confirmDelete = null)}>Cancel</Button>
									</div>
								{:else}
									<Button variant="ghost" size="sm" onclick={() => (confirmDelete = node.id)}>Delete</Button>
								{/if}
							</Table.Cell>
						</Table.Row>
					{/each}
				</Table.Body>
			</Table.Root>
		{/if}
	</Card.Content>
</Card.Root>
