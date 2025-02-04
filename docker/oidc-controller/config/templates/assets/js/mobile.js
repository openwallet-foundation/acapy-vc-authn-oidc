export const getBrowser = () => {
	let userAgent = navigator.userAgent || navigator.vendor;

	if (/android/i.test(userAgent)) {
		return "Android";
	}

	if (
		/iPad|iPhone|iPod/.test(userAgent) ||
		(/Macintosh/.test(userAgent) && "ontouchend" in document) ||
		(navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1) ||
		(navigator.vendor && navigator.vendor.indexOf("Apple") > -1)
	) {
		return "iOS";
	}

	return "unknown";
};

export const isMobile = () =>
	getBrowser() === "Android" || getBrowser() === "iOS";
