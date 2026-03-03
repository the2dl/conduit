<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type PolicyRule } from '$lib/api';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import * as Card from '$lib/components/ui/card';
	import * as Table from '$lib/components/ui/table';
	import * as Select from '$lib/components/ui/select';

	let policies = $state<PolicyRule[]>([]);
	let showAdd = $state(false);
	let form = $state<PolicyRule>({
		id: '', priority: 10, name: '', enabled: true,
		categories: [], domains: [], users: [], groups: [],
		action: 'block'
	});
	let categoriesStr = $state('');
	let domainsStr = $state('');
	let usersStr = $state('');
	let groupsStr = $state('');

	async function load() {
		try { policies = await api.policies.list(); } catch { /* ignore */ }
	}

	function resetForm() {
		form = { id: '', priority: 10, name: '', enabled: true, categories: [], domains: [], users: [], groups: [], action: 'block' };
		categoriesStr = ''; domainsStr = ''; usersStr = ''; groupsStr = '';
	}

	async function save() {
		const rule: PolicyRule = {
			...form,
			id: form.id || crypto.randomUUID().slice(0, 8),
			categories: categoriesStr.split(',').map(s => s.trim()).filter(Boolean),
			domains: domainsStr.split(',').map(s => s.trim()).filter(Boolean),
			users: usersStr.split(',').map(s => s.trim()).filter(Boolean),
			groups: groupsStr.split(',').map(s => s.trim()).filter(Boolean),
		};
		await api.policies.create(rule);
		showAdd = false;
		resetForm();
		await load();
	}

	async function remove(id: string) {
		await api.policies.remove(id);
		await load();
	}

	async function toggle(rule: PolicyRule) {
		await api.policies.update({ ...rule, enabled: !rule.enabled });
		await load();
	}

	function onActionChange(val: string | undefined) {
		if (val) form.action = val as PolicyRule['action'];
	}

	onMount(load);
</script>

<div class="mb-6">
	<h2 class="text-2xl font-semibold">Policies</h2>
	<p class="text-sm text-muted-foreground mt-1">Manage blocking and allow rules</p>
</div>

<div class="mb-4">
	<Button onclick={() => { showAdd = !showAdd; if (showAdd) resetForm(); }}>
		{showAdd ? 'Cancel' : 'Add Policy'}
	</Button>
</div>

{#if showAdd}
	<Card.Root class="mb-4">
		<Card.Content class="pt-6">
			<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
				<div class="space-y-2">
					<Label>Name</Label>
					<Input type="text" bind:value={form.name} placeholder="Block social media" />
				</div>
				<div class="space-y-2">
					<Label>Priority (lower = first)</Label>
					<Input type="number" bind:value={form.priority} />
				</div>
				<div class="space-y-2">
					<Label>Action</Label>
					<Select.Root type="single" value={form.action} onValueChange={onActionChange}>
						<Select.Trigger class="w-full">
							{form.action === 'block' ? 'Block' : form.action === 'allow' ? 'Allow' : 'Log Only'}
						</Select.Trigger>
						<Select.Content>
							<Select.Item value="block" label="Block" />
							<Select.Item value="allow" label="Allow" />
							<Select.Item value="log" label="Log Only" />
						</Select.Content>
					</Select.Root>
				</div>
				<div class="space-y-2">
					<Label>Categories (comma-separated)</Label>
					<Input type="text" bind:value={categoriesStr} placeholder="social,gaming" />
				</div>
				<div class="space-y-2">
					<Label>Domains (comma-separated, supports *.example.com)</Label>
					<Input type="text" bind:value={domainsStr} placeholder="*.facebook.com, twitter.com" />
				</div>
				<div class="space-y-2">
					<Label>Users (comma-separated)</Label>
					<Input type="text" bind:value={usersStr} placeholder="john, jane" />
				</div>
				<div class="space-y-2">
					<Label>Groups (comma-separated)</Label>
					<Input type="text" bind:value={groupsStr} placeholder="marketing, engineering" />
				</div>
			</div>
			<Button onclick={save} class="mt-4">Save Policy</Button>
		</Card.Content>
	</Card.Root>
{/if}

<Card.Root class="overflow-x-auto">
	<Card.Content class="pt-6">
		{#if policies.length === 0}
			<p class="text-sm text-muted-foreground">No policies defined</p>
		{:else}
			<Table.Root>
				<Table.Header>
					<Table.Row>
						<Table.Head>Priority</Table.Head>
						<Table.Head>Name</Table.Head>
						<Table.Head>Action</Table.Head>
						<Table.Head>Categories</Table.Head>
						<Table.Head>Domains</Table.Head>
						<Table.Head>Enabled</Table.Head>
						<Table.Head>Actions</Table.Head>
					</Table.Row>
				</Table.Header>
				<Table.Body>
					{#each policies as p}
						<Table.Row class={p.enabled ? '' : 'opacity-50'}>
							<Table.Cell class="font-mono">{p.priority}</Table.Cell>
							<Table.Cell>{p.name}</Table.Cell>
							<Table.Cell><span class="badge-{p.action} px-2 py-0.5 rounded text-xs font-semibold uppercase">{p.action}</span></Table.Cell>
							<Table.Cell>{p.categories.join(', ') || '*'}</Table.Cell>
							<Table.Cell>{p.domains.join(', ') || '*'}</Table.Cell>
							<Table.Cell>
								<Button variant="outline" size="sm" onclick={() => toggle(p)}>
									{p.enabled ? 'On' : 'Off'}
								</Button>
							</Table.Cell>
							<Table.Cell>
								<Button variant="destructive" size="sm" onclick={() => remove(p.id)}>Delete</Button>
							</Table.Cell>
						</Table.Row>
					{/each}
				</Table.Body>
			</Table.Root>
		{/if}
	</Card.Content>
</Card.Root>
