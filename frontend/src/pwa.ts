export function registerAppServiceWorker() {
  if (!import.meta.env.PROD || !("serviceWorker" in navigator)) {
    return;
  }

  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/app-sw.js", { scope: "/" }).catch((err) => {
      console.error("app service worker registration failed", err);
    });
  });
}
