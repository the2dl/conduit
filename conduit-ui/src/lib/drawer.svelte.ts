import { api, type Health, type PolicyRule, type DlpRule } from './api';
import { showToast } from './toast.svelte';

export interface PolicyDraft {
	id?: string;
	name: string;
	priority: string;
	action: 'block' | 'allow' | 'log';
	cats: string[];
	domains: string;
	users: string;
	groups: string;
}

export interface DlpDraft {
	id?: string;
	name: string;
	pattern: string;
	action: 'log' | 'block' | 'redact';
	sample: string;
	builtin?: boolean;
	allowed_domains: string;
}

const DEFAULT_SAMPLE = 'invoice PROJ-204918 paid with 4111 1111 1111 1111\nkey=AKIAIOSFODNN7EXAMPLE ssn 078-05-1120';

let activeSheet = $state<'policy' | 'dlp' | 'bulk_categories' | null>(null);
let policyDraft = $state<PolicyDraft>({
	name: '',
	priority: '10',
	action: 'block',
	cats: [],
	domains: '',
	users: '',
	groups: ''
});
let dlpDraft = $state<DlpDraft>({
	name: '',
	pattern: '',
	action: 'log',
	sample: DEFAULT_SAMPLE,
	allowed_domains: ''
});

let policyCount = $state(0);
let dlpCount = $state(0);
let nodeCount = $state(0);
let health = $state<Health>({ status: 'healthy', dragonfly: true, version: '0.1.0' });
let config = $state<Record<string, string>>({
	prevention_mode: 'false',
	tls_intercept: 'true',
	dga_prevention: 'false',
	dga_threshold: '3.5',
	threat_prevention: 'false',
	threat_block_threshold: '0.7'
});

let onPolicySaved: (() => Promise<void> | void) | null = null;
let onDlpSaved: (() => Promise<void> | void) | null = null;

export const drawer = {
	get activeSheet() { return activeSheet; },
	get policyDraft() { return policyDraft; },
	get dlpDraft() { return dlpDraft; },
	get policyCount() { return policyCount; },
	get dlpCount() { return dlpCount; },
	get nodeCount() { return nodeCount; },
	get health() { return health; },
	get config() { return config; },

	setPolicySavedCallback(cb: () => Promise<void> | void) {
		onPolicySaved = cb;
	},
	setDlpSavedCallback(cb: () => Promise<void> | void) {
		onDlpSaved = cb;
	},

	async refreshGlobal() {
		try {
			const [h, cfg, pList, dList, nList] = await Promise.all([
				api.health().catch(() => health),
				api.config.get().catch(() => config),
				api.policies.list().catch(() => []),
				api.dlp.list().catch(() => []),
				api.nodes.list().catch(() => [])
			]);
			health = h;
			config = cfg;
			policyCount = pList.length;
			dlpCount = dList.length;
			nodeCount = nList.length;
		} catch {
			/* ignore */
		}
	},

	openPolicy(preset?: Partial<PolicyDraft>) {
		policyDraft = {
			name: preset?.name ?? '',
			priority: preset?.priority ?? String((policyCount + 1) * 10),
			action: preset?.action ?? 'block',
			cats: preset?.cats ?? [],
			domains: preset?.domains ?? '',
			users: preset?.users ?? '',
			groups: preset?.groups ?? '',
			id: preset?.id
		};
		activeSheet = 'policy';
	},

	openDlp(preset?: Partial<DlpDraft> & { allowed_domains?: string | string[] }) {
		const allowed = Array.isArray(preset?.allowed_domains)
			? preset.allowed_domains.join(' ')
			: (preset?.allowed_domains ?? '');
		dlpDraft = {
			name: preset?.name ?? '',
			pattern: preset?.pattern ?? 'PROJ-\\d{6}',
			action: preset?.action ?? 'log',
			sample: preset?.sample ?? DEFAULT_SAMPLE,
			id: preset?.id,
			builtin: preset?.builtin ?? false,
			allowed_domains: allowed
		};
		activeSheet = 'dlp';
	},

	openBulkCategories() {
		activeSheet = 'bulk_categories';
	},

	close() {
		activeSheet = null;
	},

	async savePolicy() {
		if (!policyDraft.name.trim()) {
			showToast('Policy name is required');
			return false;
		}
		const cats = policyDraft.cats;
		const domains = policyDraft.domains.split(/[\s,]+/).filter(Boolean);
		if (cats.length === 0 && domains.length === 0) {
			showToast('At least one category or domain match is required');
			return false;
		}

		const rule: PolicyRule = {
			id: policyDraft.id || crypto.randomUUID().slice(0, 8),
			name: policyDraft.name.trim(),
			priority: parseInt(policyDraft.priority, 10) || 10,
			action: policyDraft.action,
			enabled: true,
			categories: cats,
			domains: domains,
			users: policyDraft.users.split(/[\s,]+/).filter(Boolean),
			groups: policyDraft.groups.split(/[\s,]+/).filter(Boolean)
		};

		try {
			if (policyDraft.id) {
				await api.policies.update(rule);
			} else {
				await api.policies.create(rule);
			}
			activeSheet = null;
			showToast('Policy saved');
			await drawer.refreshGlobal();
			if (onPolicySaved) await onPolicySaved();
			return true;
		} catch (e: any) {
			showToast(e.message || 'Failed to save policy');
			return false;
		}
	},

	async saveDlp() {
		if (!dlpDraft.name.trim() || !dlpDraft.pattern.trim()) {
			showToast('Name and a valid regex pattern are required');
			return false;
		}

		try {
			new RegExp(dlpDraft.pattern);
		} catch (err: any) {
			showToast('Invalid regular expression');
			return false;
		}

		const allowedDomains = dlpDraft.allowed_domains.split(/[\s,]+/).filter(Boolean);
		try {
			if (dlpDraft.id) {
				await api.dlp.update({
					id: dlpDraft.id,
					name: dlpDraft.name.trim(),
					regex: dlpDraft.pattern.trim(),
					action: dlpDraft.action,
					enabled: true,
					builtin: dlpDraft.builtin ?? false,
					allowed_domains: allowedDomains
				});
			} else {
				await api.dlp.create({
					name: dlpDraft.name.trim(),
					regex: dlpDraft.pattern.trim(),
					action: dlpDraft.action,
					enabled: true,
					allowed_domains: allowedDomains
				});
			}
			activeSheet = null;
			showToast('Rule saved');
			await drawer.refreshGlobal();
			if (onDlpSaved) await onDlpSaved();
			return true;
		} catch (e: any) {
			showToast(e.message || 'Failed to save DLP rule');
			return false;
		}
	}
};
