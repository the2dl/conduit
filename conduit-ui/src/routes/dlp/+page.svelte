<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type DlpRule } from '$lib/api';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import * as Card from '$lib/components/ui/card';
	import * as Table from '$lib/components/ui/table';
	import * as Select from '$lib/components/ui/select';

	let rules = $state<DlpRule[]>([]);
	let showAdd = $state(false);
	let name = $state('');
	let regex = $state('');
	let action = $state<'log' | 'block' | 'redact'>('log');
	let error = $state('');
	let editingId = $state<string | null>(null);
	let editName = $state('');
	let editRegex = $state('');
	let editAction = $state<'log' | 'block' | 'redact'>('log');
	let editError = $state('');

	async function load() {
		try { rules = await api.dlp.list(); } catch { /* ignore */ }
	}

	function resetForm() {
		name = ''; regex = ''; action = 'log'; error = '';
	}

	async function save() {
		error = '';
		if (!name.trim() || !regex.trim()) {
			error = 'Name and regex are required';
			return;
		}
		try {
			await api.dlp.create({ name: name.trim(), regex: regex.trim(), action, enabled: true });
			showAdd = false;
			resetForm();
			await load();
		} catch (e: any) {
			error = e.message || 'Failed to create rule';
		}
	}

	async function remove(id: string) {
		await api.dlp.remove(id);
		await load();
	}

	async function toggle(rule: DlpRule) {
		await api.dlp.update({ ...rule, enabled: !rule.enabled });
		await load();
	}

	function startEdit(rule: DlpRule) {
		editingId = rule.id;
		editName = rule.name;
		editRegex = rule.regex;
		editAction = rule.action;
		editError = '';
	}

	function cancelEdit() {
		editingId = null;
		editError = '';
	}

	async function saveEdit(rule: DlpRule) {
		editError = '';
		if (!editName.trim() || !editRegex.trim()) {
			editError = 'Name and regex are required';
			return;
		}
		try {
			await api.dlp.update({
				...rule,
				name: editName.trim(),
				regex: editRegex.trim(),
				action: editAction
			});
			editingId = null;
			await load();
		} catch (e: any) {
			editError = e.message || 'Failed to update rule';
		}
	}

	function onActionChange(val: string | undefined) {
		if (val) action = val as DlpRule['action'];
	}

	function onEditActionChange(val: string | undefined) {
		if (val) editAction = val as DlpRule['action'];
	}

	onMount(load);
</script>

<div class="mb-6">
	<h2 class="text-2xl font-semibold">Data Loss Prevention</h2>
	<p class="text-sm text-muted-foreground mt-1">Manage DLP rules that scan response bodies for sensitive data</p>
</div>

<div class="mb-4">
	<Button onclick={() => { showAdd = !showAdd; if (showAdd) resetForm(); }}>
		{showAdd ? 'Cancel' : 'Add Rule'}
	</Button>
</div>

{#if showAdd}
	<Card.Root class="mb-4">
		<Card.Content class="pt-6">
			<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
				<div class="space-y-2">
					<Label>Name</Label>
					<Input type="text" bind:value={name} placeholder="e.g. Internal Project IDs" />
				</div>
				<div class="space-y-2">
					<Label>Regex Pattern</Label>
					<Input type="text" bind:value={regex} placeholder="PROJ-\d{'{'}6{'}'}" class="font-mono text-sm" />
				</div>
				<div class="space-y-2">
					<Label>Action</Label>
					<Select.Root type="single" value={action} onValueChange={onActionChange}>
						<Select.Trigger class="w-full">
							{action === 'block' ? 'Block' : action === 'redact' ? 'Redact' : 'Log Only'}
						</Select.Trigger>
						<Select.Content>
							<Select.Item value="log" label="Log Only" />
							<Select.Item value="block" label="Block" />
							<Select.Item value="redact" label="Redact" />
						</Select.Content>
					</Select.Root>
				</div>
			</div>
			{#if error}
				<p class="text-sm text-destructive mt-2">{error}</p>
			{/if}
			<Button onclick={save} class="mt-4">Save Rule</Button>
		</Card.Content>
	</Card.Root>
{/if}

<Card.Root class="overflow-x-auto">
	<Card.Content class="pt-6">
		{#if rules.length === 0}
			<p class="text-sm text-muted-foreground">No DLP rules defined</p>
		{:else}
			<Table.Root>
				<Table.Header>
					<Table.Row>
						<Table.Head>Name</Table.Head>
						<Table.Head>Pattern</Table.Head>
						<Table.Head>Action</Table.Head>
						<Table.Head>Type</Table.Head>
						<Table.Head>Enabled</Table.Head>
						<Table.Head>Actions</Table.Head>
					</Table.Row>
				</Table.Header>
				<Table.Body>
					{#each rules as rule}
						{#if editingId === rule.id}
							<Table.Row>
								<Table.Cell>
									<Input type="text" bind:value={editName} class="h-8 text-sm" />
								</Table.Cell>
								<Table.Cell>
									<Input type="text" bind:value={editRegex} class="h-8 text-sm font-mono" />
								</Table.Cell>
								<Table.Cell>
									<Select.Root type="single" value={editAction} onValueChange={onEditActionChange}>
										<Select.Trigger class="h-8 text-sm w-24">
											{editAction === 'block' ? 'Block' : editAction === 'redact' ? 'Redact' : 'Log'}
										</Select.Trigger>
										<Select.Content>
											<Select.Item value="log" label="Log Only" />
											<Select.Item value="block" label="Block" />
											<Select.Item value="redact" label="Redact" />
										</Select.Content>
									</Select.Root>
								</Table.Cell>
								<Table.Cell>
									<span class="text-xs text-muted-foreground">{rule.builtin ? 'Built-in' : 'Custom'}</span>
								</Table.Cell>
								<Table.Cell></Table.Cell>
								<Table.Cell>
									<div class="flex gap-1">
										<Button variant="outline" size="sm" onclick={() => saveEdit(rule)}>Save</Button>
										<Button variant="ghost" size="sm" onclick={cancelEdit}>Cancel</Button>
									</div>
									{#if editError}
										<p class="text-xs text-destructive mt-1">{editError}</p>
									{/if}
								</Table.Cell>
							</Table.Row>
						{:else}
							<Table.Row class={rule.enabled ? '' : 'opacity-50'}>
								<Table.Cell class="font-medium">{rule.name}</Table.Cell>
								<Table.Cell>
									<code class="text-xs font-mono bg-muted px-1.5 py-0.5 rounded max-w-xs truncate block">{rule.regex}</code>
								</Table.Cell>
								<Table.Cell>
									<span class="badge-{rule.action} px-2 py-0.5 rounded text-xs font-semibold uppercase">{rule.action}</span>
								</Table.Cell>
								<Table.Cell>
									<span class="text-xs text-muted-foreground">{rule.builtin ? 'Built-in' : 'Custom'}</span>
								</Table.Cell>
								<Table.Cell>
									<Button variant="outline" size="sm" onclick={() => toggle(rule)}>
										{rule.enabled ? 'On' : 'Off'}
									</Button>
								</Table.Cell>
								<Table.Cell>
									<div class="flex gap-1">
										<Button variant="outline" size="sm" onclick={() => startEdit(rule)}>Edit</Button>
										{#if !rule.builtin}
											<Button variant="destructive" size="sm" onclick={() => remove(rule.id)}>Delete</Button>
										{/if}
									</div>
								</Table.Cell>
							</Table.Row>
						{/if}
					{/each}
				</Table.Body>
			</Table.Root>
		{/if}
	</Card.Content>
</Card.Root>
