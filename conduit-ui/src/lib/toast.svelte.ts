let message = $state('');
let visible = $state(false);
let timer: ReturnType<typeof setTimeout> | null = null;

export function showToast(msg: string) {
	message = msg;
	visible = true;
	if (timer) clearTimeout(timer);
	timer = setTimeout(() => {
		visible = false;
	}, 2200);
}

export const toast = {
	get message() {
		return message;
	},
	get visible() {
		return visible;
	}
};
