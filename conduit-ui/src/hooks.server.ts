import type { Handle } from '@sveltejs/kit';

const API_BACKEND = 'http://localhost:8443';

export const handle: Handle = async ({ event, resolve }) => {
	if (event.url.pathname.startsWith('/api/')) {
		const target = `${API_BACKEND}${event.url.pathname}${event.url.search}`;
		const body = event.request.method !== 'GET' && event.request.method !== 'HEAD'
			? await event.request.text()
			: undefined;
		const res = await fetch(target, {
			method: event.request.method,
			headers: {
				'content-type': event.request.headers.get('content-type') || 'application/json'
			},
			body
		});
		return new Response(res.body, {
			status: res.status,
			statusText: res.statusText,
			headers: res.headers
		});
	}
	return resolve(event);
};
