const API_BASE = '/api/v1';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
	const res = await fetch(`${API_BASE}${path}`, {
		headers: { 'Content-Type': 'application/json', ...options?.headers },
		...options
	});
	if (!res.ok) throw new Error(`API error: ${res.status}`);
	const text = await res.text();
	if (!text) return undefined as T;
	return JSON.parse(text);
}

export interface Stats {
	total_requests: number;
	blocked_requests: number;
	active_connections: number;
	tls_intercepted: number;
	cache_hits: number;
	cache_misses: number;
	nodes?: NodeStats[];
}

export interface NodeStats {
	node_id: string;
	node_name: string;
	total_requests: number;
	blocked_requests: number;
	tls_intercepted: number;
	active_connections: number;
	online: boolean;
}

export interface LogEntry {
	id: string;
	timestamp: string;
	client_ip: string;
	username: string | null;
	method: string;
	scheme: string;
	host: string;
	port: number;
	path: string;
	full_url: string;
	category: string | null;
	action: 'allow' | 'block' | 'log';
	status_code: number;
	duration_ms: number;
	tls_intercepted: boolean;
	node_id: string | null;
	node_name: string | null;
	block_reason?: string | null;
	rule_name?: string | null;
	threat_signals?: { name: string; score: number; tier: string }[] | null;
}

export interface CategoryEntry {
	domain: string;
	category: string;
}

export interface PaginatedCategories {
	entries: CategoryEntry[];
	next_cursor: string | null;
	total_estimate: number | null;
}

export interface PolicyRule {
	id: string;
	priority: number;
	name: string;
	enabled: boolean;
	categories: string[];
	domains: string[];
	users: string[];
	groups: string[];
	action: 'allow' | 'block' | 'log';
}

export interface Health {
	status: string;
	dragonfly: boolean;
	version: string;
}

export interface NodeHeartbeat {
	node_id: string;
	timestamp: string;
	uptime_secs: number;
	active_connections: number;
	total_requests: number;
	version: string;
	listen_addr: string;
	host: string;
}

export interface NodeInfo {
	id: string;
	name: string;
	status: 'pending' | 'active' | 'inactive';
	dragonfly_user: string;
	created_at: string;
	enrolled_at: string | null;
	heartbeat: NodeHeartbeat | null;
	online: boolean;
	heartbeat_verified: boolean;
}

export interface NodeEnrollment {
	node_id: string;
	dragonfly_url: string;
	dragonfly_user: string;
	dragonfly_password: string;
	enrollment_token: string;
	hmac_key: string;
}

export interface DlpRule {
	id: string;
	name: string;
	regex: string;
	action: 'log' | 'block' | 'redact';
	enabled: boolean;
	builtin: boolean;
}

export const api = {
	health: () => request<Health>('/health'),
	stats: () => request<Stats>('/stats'),
	logs: async (params?: Record<string, string>) => {
		const qs = params ? '?' + new URLSearchParams(params).toString() : '';
		const res = await request<{ entries: LogEntry[]; next_cursor: string | null; total: number }>(`/logs${qs}`);
		return res.entries;
	},
	categories: {
		list: (params?: Record<string, string>) => {
			const qs = params ? '?' + new URLSearchParams(params).toString() : '';
			return request<PaginatedCategories>(`/categories${qs}`);
		},
		add: (entry: CategoryEntry) =>
			request<void>('/categories', { method: 'POST', body: JSON.stringify(entry) }),
		remove: (domain: string) =>
			request<void>(`/categories?domain=${encodeURIComponent(domain)}`, { method: 'DELETE' }),
		import: (csv: string) =>
			fetch(`${API_BASE}/categories/import`, { method: 'POST', body: csv })
	},
	policies: {
		list: () => request<PolicyRule[]>('/policies'),
		create: (rule: PolicyRule) =>
			request<void>('/policies', { method: 'POST', body: JSON.stringify(rule) }),
		update: (rule: PolicyRule) =>
			request<void>('/policies', { method: 'PUT', body: JSON.stringify(rule) }),
		remove: (id: string) =>
			request<void>('/policies', { method: 'DELETE', body: JSON.stringify({ id }) })
	},
	dlp: {
		list: () => request<DlpRule[]>('/dlp/rules'),
		create: (rule: Omit<DlpRule, 'id' | 'builtin'>) =>
			request<DlpRule>('/dlp/rules', { method: 'POST', body: JSON.stringify(rule) }),
		update: (rule: DlpRule) =>
			request<DlpRule>('/dlp/rules', { method: 'PUT', body: JSON.stringify(rule) }),
		remove: (id: string) =>
			request<void>('/dlp/rules', { method: 'DELETE', body: JSON.stringify({ id }) })
	},
	config: {
		get: () => request<Record<string, string>>('/config'),
		update: (config: Record<string, string>) =>
			request<void>('/config', { method: 'PUT', body: JSON.stringify(config) })
	},
	nodes: {
		list: () => request<NodeInfo[]>('/nodes'),
		create: (name: string) =>
			request<NodeEnrollment>('/nodes', { method: 'POST', body: JSON.stringify({ name }) }),
		get: (id: string) => request<NodeInfo>(`/nodes/${encodeURIComponent(id)}`),
		remove: (id: string) =>
			request<void>(`/nodes/${encodeURIComponent(id)}`, { method: 'DELETE' })
	}
};
