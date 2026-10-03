<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type Health } from '$lib/api';
	import { drawer } from '$lib/drawer.svelte';
	import { showToast } from '$lib/toast.svelte';

	let health = $state<Health>({ status: 'healthy', dragonfly: true, version: '0.1.0' });
	let savedConfig = $state<Record<string, string>>({
		tls_intercept: 'true',
		prevention_mode: 'false',
		dga_prevention: 'false',
		dga_threshold: '3.5',
		threat_prevention: 'false',
		threat_block_threshold: '0.7',
		auto_categorize_enabled: 'true',
		auto_categorize_agent: 'agy',
		auto_categorize_ut1: 'true'
	});
	let draftConfig = $state<Record<string, string>>({
		tls_intercept: 'true',
		prevention_mode: 'false',
		dga_prevention: 'false',
		dga_threshold: '3.5',
		threat_prevention: 'false',
		threat_block_threshold: '0.7',
		auto_categorize_enabled: 'true',
		auto_categorize_agent: 'agy',
		auto_categorize_ut1: 'true'
	});
	let loading = $state(true);

	// Auto-categorization state
	let pendingCount = $state(0);
	let availableAgents = $state<string[]>(['agy', 'codex', 'claude']);
	let runningCategorization = $state(false);

	// CA cert state
	let caSubject = $state('CN=conduit root ca, O=conduit proxy, C=US');
	let caFingerprint = $state(
		'AE:0D:0E:CA:E3:EC:E3:B0:E3:ED:8A:FE:FC:DB:42:71:AC:88:E4:7F:62:C9:13:84:FD:39:39:F5:92:51:07:08'
	);
	let caValidUntil = $state('2036-09-26');
	let caPemRaw = $state<string>('');
	let caDerRaw = $state<Uint8Array | null>(null);

	// Key count in Dragonfly
	let dragonflyKeys = $state('1,000,031');

	let settingsDirty = $derived(
		draftConfig.tls_intercept !== savedConfig.tls_intercept ||
			draftConfig.prevention_mode !== savedConfig.prevention_mode ||
			draftConfig.dga_prevention !== savedConfig.dga_prevention ||
			draftConfig.dga_threshold !== savedConfig.dga_threshold ||
			draftConfig.threat_prevention !== savedConfig.threat_prevention ||
			draftConfig.threat_block_threshold !== savedConfig.threat_block_threshold ||
			draftConfig.auto_categorize_enabled !== savedConfig.auto_categorize_enabled ||
			draftConfig.auto_categorize_agent !== savedConfig.auto_categorize_agent ||
			draftConfig.auto_categorize_ut1 !== savedConfig.auto_categorize_ut1
	);

	let tlsOn = $derived(
		draftConfig.tls_intercept === 'true' || (draftConfig.tls_intercept as any) === true
	);
	let prevOn = $derived(
		draftConfig.prevention_mode === 'true' || (draftConfig.prevention_mode as any) === true
	);
	let dgaOn = $derived(
		draftConfig.dga_prevention === 'true' || (draftConfig.dga_prevention as any) === true
	);
	let threatOn = $derived(
		draftConfig.threat_prevention === 'true' || (draftConfig.threat_prevention as any) === true
	);
	let autoCatOn = $derived(
		draftConfig.auto_categorize_enabled === 'true' || (draftConfig.auto_categorize_enabled as any) === true
	);
	let autoUt1On = $derived(
		draftConfig.auto_categorize_ut1 === 'true' || (draftConfig.auto_categorize_ut1 as any) === true
	);

	function toggleAutoCat() {
		draftConfig.auto_categorize_enabled = autoCatOn ? 'false' : 'true';
	}

	function toggleAutoUt1() {
		draftConfig.auto_categorize_ut1 = autoUt1On ? 'false' : 'true';
	}

	function toggleTls() {
		draftConfig.tls_intercept = tlsOn ? 'false' : 'true';
	}

	function togglePrev() {
		draftConfig.prevention_mode = prevOn ? 'false' : 'true';
	}

	function toggleDga() {
		draftConfig.dga_prevention = dgaOn ? 'false' : 'true';
	}

	function toggleThreat() {
		draftConfig.threat_prevention = threatOn ? 'false' : 'true';
	}

	function discardSettings() {
		draftConfig = { ...savedConfig };
	}

	async function saveSettings() {
		try {
			await api.config.update(draftConfig);
			savedConfig = { ...draftConfig };
			drawer.refreshGlobal();
			showToast('Settings saved · all nodes updated');
		} catch (err: any) {
			showToast(err.message || 'Failed to save settings');
		}
	}

	async function loadCA() {
		try {
			const res = await fetch('/api/v1/ca/cert');
			if (res.ok) {
				const pem = await res.text();
				caPemRaw = pem;
				const b64 = pem.replace(/-----[^\n]+-----/g, '').replace(/\s+/g, '');
				const binary = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
				caDerRaw = binary;
				const hashBuf = await crypto.subtle.digest('SHA-256', binary);
				const hashArr = Array.from(new Uint8Array(hashBuf));
				caFingerprint = hashArr
					.map((b) => b.toString(16).padStart(2, '0').toUpperCase())
					.join(':');
			}
		} catch {
			/* fallback to default */
		}
	}

	function downloadPem() {
		if (!caPemRaw) {
			window.open('/api/v1/ca/cert', '_blank');
			return;
		}
		const blob = new Blob([caPemRaw], { type: 'application/x-pem-file' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = 'conduit-ca.pem';
		a.click();
		URL.revokeObjectURL(url);
		showToast('Downloaded conduit-ca.pem');
	}

	function downloadDer() {
		if (!caDerRaw) {
			downloadPem();
			return;
		}
		const blob = new Blob([caDerRaw.buffer as ArrayBuffer], { type: 'application/x-x509-ca-cert' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = 'conduit-ca.der';
		a.click();
		URL.revokeObjectURL(url);
		showToast('Downloaded conduit-ca.der');
	}

	async function loadCategorizationInfo() {
		try {
			const [pending, ags] = await Promise.all([
				api.categories.pending(1).catch(() => ({ count: 0, domains: [] })),
				api.categories.agents().catch(() => ({ available: ['agy'], default: 'agy' }))
			]);
			pendingCount = pending.count;
			if (ags.available && ags.available.length > 0) {
				availableAgents = ags.available;
			}
		} catch {
			/* ignore */
		}
	}

	async function triggerCategorizationNow() {
		runningCategorization = true;
		try {
			const res = await api.categories.autoCategorize({
				agent: draftConfig.auto_categorize_agent,
				sync_ut1: autoUt1On
			});
			if (res.success) {
				showToast(`Categorized ${res.categorized_count} domains using ${res.agent_used}`);
			} else {
				showToast(`Categorization completed with warnings: ${res.error || 'Check logs'}`);
			}
			await loadCategorizationInfo();
		} catch (err: any) {
			showToast(err.message || 'Auto-categorization failed');
		} finally {
			runningCategorization = false;
		}
	}

	onMount(async () => {
		try {
			const [cfg, h] = await Promise.all([
				api.config.get().catch(() => ({ prevention_mode: 'false', tls_intercept: 'true' })),
				api.health().catch(() => ({ status: 'healthy', dragonfly: true, version: '0.1.0' }))
			]);
			savedConfig = { ...cfg };
			draftConfig = { ...cfg };
			health = h;
			if ((h as any).dragonfly_keys) {
				dragonflyKeys = Number((h as any).dragonfly_keys).toLocaleString();
			}
		} finally {
			loading = false;
		}
		loadCA();
		loadCategorizationInfo();
	});
</script>

<header
	class="h-14 flex-none flex items-center px-7 border-b border-[#1F1F24] bg-[#0A0A0B]"
>
	<span class="text-[15px] font-semibold text-[#E6E6E8]">Settings</span>
</header>

<div class="flex-1 overflow-auto px-7 pt-2 pb-24">
	<div class="max-w-[880px] flex flex-col">
		<!-- Section: Interception -->
		<div
			class="grid grid-cols-[220px_minmax(0,1fr)] gap-8 py-6 border-b border-[#1F1F24]"
		>
			<div class="flex flex-col gap-1">
				<span class="font-semibold text-[#E6E6E8]">Interception</span>
				<span class="text-[#6B6B73] text-[12.5px] leading-[19px]">Applies to every node.</span>
			</div>
			<div class="flex flex-col border border-[#1F1F24] rounded-lg bg-[#111113]">
				<div class="flex items-center gap-4 p-3.5 px-4 border-b border-[#1F1F24]">
					<div class="flex-1 flex flex-col gap-0.5">
						<span class="font-medium text-[#E6E6E8] text-[13px]">TLS interception</span>
						<span class="text-[#6B6B73] text-[12.5px]">
							Decrypt HTTPS with the conduit CA so policies and DLP can inspect bodies.
						</span>
						<span class="font-mono text-[11px] text-[#55555C]">tls_intercept</span>
					</div>
					<button
						type="button"
						aria-label="Toggle TLS interception"
						onclick={toggleTls}
						class="w-[34px] h-5 flex-none rounded-[10px] p-0.5 flex cursor-pointer transition-colors {tlsOn
							? 'bg-[#ED2377] justify-end'
							: 'bg-[#2A2A30] justify-start'}"
					>
						<span class="w-4 h-4 rounded-full bg-white block shadow-sm"></span>
					</button>
				</div>
				<div class="flex items-center gap-4 p-3.5 px-4">
					<div class="flex-1 flex flex-col gap-0.5">
						<span class="font-medium text-[#E6E6E8] text-[13px]">Prevention mode</span>
						<span class="text-[#6B6B73] text-[12.5px]">
							Enforce block actions. When off, matches are logged only.
						</span>
						<span class="font-mono text-[11px] text-[#55555C]">prevention_mode</span>
					</div>
					<button
						type="button"
						aria-label="Toggle Prevention mode"
						onclick={togglePrev}
						class="w-[34px] h-5 flex-none rounded-[10px] p-0.5 flex cursor-pointer transition-colors {prevOn
							? 'bg-[#ED2377] justify-end'
							: 'bg-[#2A2A30] justify-start'}"
					>
						<span class="w-4 h-4 rounded-full bg-white block shadow-sm"></span>
					</button>
				</div>
			</div>
		</div>

		<!-- Section: Threat & DGA Intelligence -->
		<div
			class="grid grid-cols-[220px_minmax(0,1fr)] gap-8 py-6 border-b border-[#1F1F24]"
		>
			<div class="flex flex-col gap-1">
				<span class="font-semibold text-[#E6E6E8]">Threat & DGA</span>
				<span class="text-[#6B6B73] text-[12.5px] leading-[19px]">
					Automated entropy detection and heuristic threat prevention.
				</span>
			</div>
			<div class="flex flex-col border border-[#1F1F24] rounded-lg bg-[#111113]">
				<!-- DGA Domain Prevention -->
				<div class="flex items-center gap-4 p-3.5 px-4 border-b border-[#1F1F24]">
					<div class="flex-1 flex flex-col gap-0.5">
						<span class="font-medium text-[#E6E6E8] text-[13px]">DGA domain prevention</span>
						<span class="text-[#6B6B73] text-[12.5px]">
							Block algorithmically generated domains with high Shannon entropy (malware C2 protection).
						</span>
						<span class="font-mono text-[11px] text-[#55555C]">dga_prevention</span>
					</div>
					<button
						type="button"
						aria-label="Toggle DGA prevention"
						onclick={toggleDga}
						class="w-[34px] h-5 flex-none rounded-[10px] p-0.5 flex cursor-pointer transition-colors {dgaOn
							? 'bg-[#ED2377] justify-end'
							: 'bg-[#2A2A30] justify-start'}"
					>
						<span class="w-4 h-4 rounded-full bg-white block shadow-sm"></span>
					</button>
				</div>

				<!-- DGA Threshold -->
				<div class="flex items-center gap-4 p-3.5 px-4 border-b border-[#1F1F24]">
					<div class="flex-1 flex flex-col gap-0.5">
						<span class="font-medium text-[#E6E6E8] text-[13px]">DGA entropy threshold</span>
						<span class="text-[#6B6B73] text-[12.5px]">
							Shannon entropy sensitivity cutoff. Default is 3.5 (standard balanced).
						</span>
						<span class="font-mono text-[11px] text-[#55555C]">dga_threshold</span>
					</div>
					<div class="flex items-center gap-2">
						<input
							type="number"
							step="0.1"
							min="2.5"
							max="5.0"
							bind:value={draftConfig.dga_threshold}
							class="w-20 h-7 px-2 border border-[#2A2A30] rounded bg-[#0A0A0B] text-[#E6E6E8] font-mono text-xs text-right focus:outline-none focus:border-[#ED2377]"
						/>
					</div>
				</div>

				<!-- Threat Score Enforcement -->
				<div class="flex items-center gap-4 p-3.5 px-4 border-b border-[#1F1F24]">
					<div class="flex-1 flex flex-col gap-0.5">
						<span class="font-medium text-[#E6E6E8] text-[13px]">Heuristic threat enforcement</span>
						<span class="text-[#6B6B73] text-[12.5px]">
							Block domains when compound threat score exceeds threshold (TLD risk, phishing keywords, NRD combos).
						</span>
						<span class="font-mono text-[11px] text-[#55555C]">threat_prevention</span>
					</div>
					<button
						type="button"
						aria-label="Toggle Threat score enforcement"
						onclick={toggleThreat}
						class="w-[34px] h-5 flex-none rounded-[10px] p-0.5 flex cursor-pointer transition-colors {threatOn
							? 'bg-[#ED2377] justify-end'
							: 'bg-[#2A2A30] justify-start'}"
					>
						<span class="w-4 h-4 rounded-full bg-white block shadow-sm"></span>
					</button>
				</div>

				<!-- Threat Score Threshold -->
				<div class="flex items-center gap-4 p-3.5 px-4">
					<div class="flex-1 flex flex-col gap-0.5">
						<span class="font-medium text-[#E6E6E8] text-[13px]">Threat block threshold</span>
						<span class="text-[#6B6B73] text-[12.5px]">
							Normalized risk score cutoff (0.00 – 1.00) required to trigger automatic block.
						</span>
						<span class="font-mono text-[11px] text-[#55555C]">threat_block_threshold</span>
					</div>
					<div class="flex items-center gap-2">
						<input
							type="number"
							step="0.05"
							min="0.1"
							max="1.0"
							bind:value={draftConfig.threat_block_threshold}
							class="w-20 h-7 px-2 border border-[#2A2A30] rounded bg-[#0A0A0B] text-[#E6E6E8] font-mono text-xs text-right focus:outline-none focus:border-[#ED2377]"
						/>
					</div>
				</div>
			</div>
		</div>

		<!-- Section: Automated Domain Categorization -->
		<div
			class="grid grid-cols-[220px_minmax(0,1fr)] gap-8 py-6 border-b border-[#1F1F24]"
		>
			<div class="flex flex-col gap-1">
				<span class="font-semibold text-[#E6E6E8]">Auto-Categorization</span>
				<span class="text-[#6B6B73] text-[12.5px] leading-[19px]">
					Automate daily domain classification using local AI agents and feed syncs.
				</span>
			</div>
			<div class="flex flex-col border border-[#1F1F24] rounded-lg bg-[#111113]">
				<!-- Enable Daily Categorization -->
				<div class="flex items-center gap-4 p-3.5 px-4 border-b border-[#1F1F24]">
					<div class="flex-1 flex flex-col gap-0.5">
						<span class="font-medium text-[#E6E6E8] text-[13px]">Daily auto-categorization</span>
						<span class="text-[#6B6B73] text-[12.5px]">
							Automatically classify uncategorized domains observed in proxy traffic.
						</span>
						<span class="font-mono text-[11px] text-[#55555C]">auto_categorize_enabled</span>
					</div>
					<button
						type="button"
						aria-label="Toggle auto-categorization"
						onclick={toggleAutoCat}
						class="w-[34px] h-5 flex-none rounded-[10px] p-0.5 flex cursor-pointer transition-colors {autoCatOn
							? 'bg-[#ED2377] justify-end'
							: 'bg-[#2A2A30] justify-start'}"
					>
						<span class="w-4 h-4 rounded-full bg-white block shadow-sm"></span>
					</button>
				</div>

				<!-- Local Agent Selection -->
				<div class="flex items-center gap-4 p-3.5 px-4 border-b border-[#1F1F24]">
					<div class="flex-1 flex flex-col gap-0.5">
						<span class="font-medium text-[#E6E6E8] text-[13px]">Local AI agent</span>
						<span class="text-[#6B6B73] text-[12.5px]">
							On-device agent used for headless domain categorization sweeps.
						</span>
						<span class="font-mono text-[11px] text-[#55555C]">auto_categorize_agent</span>
					</div>
					<div class="flex items-center gap-2">
						<select
							bind:value={draftConfig.auto_categorize_agent}
							class="h-7 px-2.5 border border-[#2A2A30] rounded bg-[#0A0A0B] text-[#E6E6E8] font-mono text-xs focus:outline-none focus:border-[#ED2377]"
						>
							<option value="none">none (no LLM)</option>
							{#each ['agy', 'codex', 'claude'] as agent}
								{@const detected = availableAgents.includes(agent)}
								<option value={agent}>
									{agent} {detected ? '(detected)' : '(not installed)'}
								</option>
							{/each}
						</select>
					</div>
				</div>

				<!-- UT1 Feed Daily Sync -->
				<div class="flex items-center gap-4 p-3.5 px-4 border-b border-[#1F1F24]">
					<div class="flex-1 flex flex-col gap-0.5">
						<span class="font-medium text-[#E6E6E8] text-[13px]">Sync UT1 categories daily</span>
						<span class="text-[#6B6B73] text-[12.5px]">
							Daily automated download and ingestion of Université Toulouse 1 Capitole taxonomy.
						</span>
						<span class="font-mono text-[11px] text-[#55555C]">auto_categorize_ut1</span>
					</div>
					<button
						type="button"
						aria-label="Toggle UT1 daily sync"
						onclick={toggleAutoUt1}
						class="w-[34px] h-5 flex-none rounded-[10px] p-0.5 flex cursor-pointer transition-colors {autoUt1On
							? 'bg-[#ED2377] justify-end'
							: 'bg-[#2A2A30] justify-start'}"
					>
						<span class="w-4 h-4 rounded-full bg-white block shadow-sm"></span>
					</button>
				</div>

				<!-- Queue Status & Run Now -->
				<div class="flex items-center justify-between gap-4 p-3.5 px-4 bg-[#141417]">
					<div class="flex items-center gap-2 text-xs">
						<span class="text-[#6B6B73]">Pending uncategorized domains:</span>
						<span class="font-mono px-2 py-0.5 rounded bg-[#1F1F24] text-[#E6E6E8] font-medium">
							{pendingCount.toLocaleString()}
						</span>
					</div>
					<button
						type="button"
						disabled={runningCategorization}
						onclick={triggerCategorizationNow}
						class="h-7 px-3 border border-[#2A2A30] rounded-md bg-[#1F1F24] hover:bg-[#2A2A30] text-[#E6E6E8] text-[12.5px] font-medium cursor-pointer transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1.5"
					>
						{#if runningCategorization}
							<span class="w-3 h-3 border-2 border-white/20 border-t-white rounded-full animate-spin"></span>
							<span>Running...</span>
						{:else}
							<span>Run Categorization Now</span>
						{/if}
					</button>
				</div>
			</div>
		</div>

		<!-- Section: CA certificate -->
		<div
			class="grid grid-cols-[220px_minmax(0,1fr)] gap-8 py-6 border-b border-[#1F1F24]"
		>
			<div class="flex flex-col gap-1">
				<span class="font-semibold text-[#E6E6E8]">CA certificate</span>
				<span class="text-[#6B6B73] text-[12.5px] leading-[19px]">
					Deploy to client trust stores so intercepted TLS doesn't warn.
				</span>
			</div>
			<div
				class="flex flex-col gap-3.5 border border-[#1F1F24] rounded-lg bg-[#111113] p-4"
			>
				<div class="grid grid-cols-[100px_minmax(0,1fr)] row-gap-2 font-mono text-xs text-[#E6E6E8]">
					<span class="font-sans text-[#6B6B73]">Subject</span>
					<span>{caSubject}</span>
					<span class="font-sans text-[#6B6B73]">SHA-256</span>
					<span class="text-[#A3A3AB] [overflow-wrap:anywhere]">{caFingerprint}</span>
					<span class="font-sans text-[#6B6B73]">Valid until</span>
					<span>{caValidUntil}</span>
				</div>
				<div class="flex gap-2 pt-1">
					<button
						type="button"
						onclick={downloadPem}
						class="h-7 px-3 border border-[#2A2A30] rounded-md bg-transparent text-[#E6E6E8] text-[12.5px] hover:bg-[#16161A] cursor-pointer transition-colors"
					>
						Download .pem
					</button>
					<button
						type="button"
						onclick={downloadDer}
						class="h-7 px-3 border border-[#2A2A30] rounded-md bg-transparent text-[#E6E6E8] text-[12.5px] hover:bg-[#16161A] cursor-pointer transition-colors"
					>
						Download .der
					</button>
				</div>
			</div>
		</div>

		<!-- Section: System -->
		<div class="grid grid-cols-[220px_minmax(0,1fr)] gap-8 py-6">
			<div class="flex flex-col gap-1">
				<span class="font-semibold text-[#E6E6E8]">System</span>
				<span class="text-[#6B6B73] text-[12.5px]">Read-only.</span>
			</div>
			<div class="grid grid-cols-[100px_minmax(0,1fr)] row-gap-2 font-mono text-xs text-[#E6E6E8]">
				<span class="font-sans text-[#6B6B73]">Status</span>
				<span class="flex items-center gap-1.5">
					<span
						class="w-1.5 h-1.5 rounded-full {health.status === 'healthy'
							? 'bg-[#4ADE80]'
							: 'bg-[#FDBA74]'}"
					></span>
					{health.status}
				</span>
				<span class="font-sans text-[#6B6B73]">Dragonfly</span>
				<span>{health.dragonfly ? 'connected' : 'disconnected'} · {dragonflyKeys} keys</span>
				<span class="font-sans text-[#6B6B73]">Version</span>
				<span>{health.version}</span>
			</div>
		</div>
	</div>
</div>

<!-- Floating Save Bar -->
{#if settingsDirty}
	<div
		class="fixed left-[252px] right-7 bottom-5 max-w-[880px] flex items-center gap-3 py-2.5 px-4 border border-[#2A2A30] rounded-lg bg-[#141417] shadow-[0_12px_32px_rgba(0,0,0,0.5)] z-20"
	>
		<span class="flex-1 text-[#A3A3AB] text-[12.5px]">
			Unsaved changes apply to all nodes on save.
		</span>
		<button
			type="button"
			onclick={discardSettings}
			class="h-7 px-3 border-none rounded-md bg-transparent text-[#A3A3AB] hover:text-[#E6E6E8] text-[12.5px] cursor-pointer transition-colors"
		>
			Discard
		</button>
		<button
			type="button"
			onclick={saveSettings}
			class="h-7 px-3 border-none rounded-md bg-[#ED2377] text-white hover:bg-[#F23D88] text-[12.5px] font-medium cursor-pointer transition-colors shadow-sm"
		>
			Save
		</button>
	</div>
{/if}
