<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type Health } from '$lib/api';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import * as Card from '$lib/components/ui/card';

	let config = $state<Record<string, string>>({});
	let health = $state<Health>({ status: 'unknown', dragonfly: false, version: '0.0.0' });
	let saved = $state(false);

	async function load() {
		try {
			config = await api.config.get();
			health = await api.health();
		} catch { /* ignore */ }
	}

	async function save() {
		await api.config.update(config);
		saved = true;
		setTimeout(() => saved = false, 2000);
	}

	function downloadCA() {
		window.open('/api/v1/ca/cert', '_blank');
	}

	onMount(load);
</script>

<div class="mb-6">
	<h2 class="text-2xl font-semibold">Settings</h2>
	<p class="text-sm text-muted-foreground mt-1">Proxy configuration and CA certificate</p>
</div>

<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
	<Card.Root>
		<Card.Header>
			<Card.Title class="text-sm uppercase tracking-wide text-muted-foreground">System Health</Card.Title>
		</Card.Header>
		<Card.Content class="space-y-3">
			<div>
				<span class="text-xs text-muted-foreground">Status:</span>
				<span class="status-dot {health.status === 'healthy' ? 'status-dot-healthy' : 'status-dot-degraded'} mx-1.5"></span>
				{health.status}
			</div>
			<div>
				<span class="text-xs text-muted-foreground">Dragonfly:</span>
				{health.dragonfly ? 'Connected' : 'Disconnected'}
			</div>
			<div>
				<span class="text-xs text-muted-foreground">Version:</span>
				{health.version}
			</div>
		</Card.Content>
	</Card.Root>

	<Card.Root>
		<Card.Header>
			<Card.Title class="text-sm uppercase tracking-wide text-muted-foreground">CA Certificate</Card.Title>
		</Card.Header>
		<Card.Content>
			<p class="text-sm text-muted-foreground mb-4">
				Download the root CA certificate to deploy to client trust stores.
				This enables TLS interception without browser warnings.
			</p>
			<Button onclick={downloadCA}>Download CA Certificate (PEM)</Button>
		</Card.Content>
	</Card.Root>
</div>

<Card.Root class="mt-6">
	<Card.Header>
		<Card.Title class="text-sm uppercase tracking-wide text-muted-foreground">Runtime Configuration</Card.Title>
	</Card.Header>
	<Card.Content>
		<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
			{#each Object.entries(config) as [key]}
				<div class="space-y-2">
					<Label>{key}</Label>
					<Input type="text" bind:value={config[key]} />
				</div>
			{/each}
		</div>
		{#if Object.keys(config).length > 0}
			<div class="mt-4 flex items-center gap-3">
				<Button onclick={save}>Save Configuration</Button>
				{#if saved}
					<span class="text-sm text-green-500">Saved!</span>
				{/if}
			</div>
		{:else}
			<p class="text-sm text-muted-foreground">No runtime configuration keys set</p>
		{/if}
	</Card.Content>
</Card.Root>
