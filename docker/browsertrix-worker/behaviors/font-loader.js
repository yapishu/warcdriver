class WARCdriverFontLoader {
  static id = "WARCdriver Remote Font Loader";
  static runInIframe = false;

  static init() {
    return {};
  }

  static isMatch() {
    return typeof document !== "undefined" && Boolean(document.fonts);
  }

  async* run(ctx) {
    const sleep = ctx?.Lib?.sleep || ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    const startedAt = Date.now();
    const maxMs = 45000;
    const sampleText = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let fontFaces = 0;
    let loadedFonts = 0;
    let failedFonts = 0;
    let scrollSteps = 0;

    const timeLeft = () => Math.max(0, maxMs - (Date.now() - startedAt));
    const withTimeout = async (promise, ms) => {
      if (ms <= 0) {
        return undefined;
      }
      return Promise.race([
        promise,
        new Promise((resolve) => setTimeout(resolve, ms)),
      ]);
    };
    const loadFonts = async () => {
      if (!document.fonts) {
        return;
      }

      const faces = Array.from(document.fonts);
      fontFaces = Math.max(fontFaces, faces.length);
      await Promise.allSettled(faces.map(async (face) => {
        if (face.status === "loaded") {
          return;
        }
        try {
          await face.load(sampleText);
        } catch (err) {
          void err;
        }
      }));

      await withTimeout(document.fonts.ready.catch(() => undefined), Math.min(1000, timeLeft()));
      loadedFonts = faces.filter((face) => face.status === "loaded").length;
      failedFonts = faces.filter((face) => face.status === "error").length;
    };

    const isRequiredSubstackImage = (raw) => {
      try {
        const host = new URL(raw, location.href).hostname.toLowerCase();
        return host === "substackcdn.com" || host.endsWith(".substackcdn.com") ||
          host === "substack-post-media.s3.amazonaws.com" || host.endsWith(".substack-post-media.s3.amazonaws.com");
      } catch (_) {
        return false;
      }
    };

    const bodyImageURLs = () => {
      const article = document.querySelector("article, .body.markup, [data-testid='post-content'], .available-content") || document.body;
      const urls = new Set();
      const add = (raw) => {
        if (!raw) return;
        const absolute = new URL(raw, location.href).href;
        if (isRequiredSubstackImage(absolute)) urls.add(absolute);
      };
      article.querySelectorAll("img").forEach((img) => {
        const srcset = img.getAttribute("srcset") || img.getAttribute("data-srcset") || "";
        const firstResponsiveSource = srcset.split(",")[0]?.trim().split(/\s+/)[0];
        add(img.currentSrc || img.getAttribute("src") || img.getAttribute("data-src") || firstResponsiveSource);
      });
      return Array.from(urls);
    };

    const loadBodyImage = async (raw) => {
      const loaded = await withTimeout(new Promise((resolve) => {
        const image = new Image();
        image.onload = () => resolve(true);
        image.onerror = () => resolve(false);
        image.src = raw;
        if (image.complete) resolve(image.naturalWidth > 0);
      }), Math.min(12000, timeLeft()));
      return loaded === true;
    };

    await withTimeout(loadFonts(), timeLeft());
    yield {msg: "remote font load pass", fontFaces, loadedFonts, failedFonts, scrollSteps};

    const root = document.scrollingElement || document.documentElement || document.body;
    if (!root) {
      return;
    }

    let lastTop = -1;
    for (let step = 0; step < 30 && timeLeft() > 250; step += 1) {
      const maxTop = Math.max(0, root.scrollHeight - window.innerHeight);
      const nextTop = Math.min(maxTop, Math.round(step * window.innerHeight * 0.85));
      if (nextTop === lastTop) {
        break;
      }
      root.scrollTop = nextTop;
      lastTop = nextTop;
      scrollSteps += 1;
      await sleep(150);
      await withTimeout(loadFonts(), Math.min(700, timeLeft()));
      if (nextTop >= maxTop) {
        break;
      }
    }

    root.scrollTop = 0;
    await sleep(100);
    await withTimeout(loadFonts(), Math.min(700, timeLeft()));
    const requiredImages = bodyImageURLs();
    let loadedImages = 0;
    let failedImages = 0;
    let cursor = 0;
    const workers = Array.from({length: Math.min(8, Math.max(1, requiredImages.length))}, async () => {
      while (cursor < requiredImages.length && timeLeft() > 250) {
        const imageURL = requiredImages[cursor++];
        if (await loadBodyImage(imageURL)) loadedImages += 1;
        else failedImages += 1;
      }
    });
    await Promise.allSettled(workers);
    failedImages += Math.max(0, requiredImages.length - loadedImages - failedImages);
    yield {
      msg: `body image capture required=${requiredImages.length} loaded=${loadedImages} failed=${failedImages} page=${location.href}`,
      fontFaces, loadedFonts, failedFonts, scrollSteps
    };
  }
}
