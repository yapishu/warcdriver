class WARCdriverFontLoader {
  static id = "WARCdriver Substack Asset Loader";
  static runInIframe = false;

  static init() {
    return {};
  }

  static isMatch() {
    if (typeof document === "undefined" || typeof location === "undefined") {
      return false;
    }
    const host = location.hostname.toLowerCase();
    return Boolean(document.fonts) && (host === "substack.com" || host.endsWith(".substack.com"));
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

    const originalSubstackImageURL = (raw) => {
      try {
        const absolute = new URL(raw, location.href).href;
        const marker = absolute.indexOf("/https%3A");
        if (marker < 0) return "";
        const original = decodeURIComponent(absolute.slice(marker + 1));
        return isRequiredSubstackImage(original) ? original : "";
      } catch (_) {
        return "";
      }
    };

    const bodyImages = () => {
      const article = document.querySelector(".body.markup") ||
        document.querySelector("[data-testid='post-content']") ||
        document.querySelector(".available-content") ||
        document.querySelector("article") ||
        document.body;
      const images = [];
      const seen = new Set();
      article.querySelectorAll("img").forEach((img) => {
        const candidates = [];
        const add = (raw) => {
          if (!raw) return;
          const absolute = new URL(raw, location.href).href;
          if (isRequiredSubstackImage(absolute) && !candidates.includes(absolute)) candidates.push(absolute);
          const original = originalSubstackImageURL(absolute);
          if (original && !candidates.includes(original)) candidates.push(original);
        };
        const srcset = img.getAttribute("srcset") || img.getAttribute("data-srcset") || "";
        add(img.currentSrc);
        add(img.getAttribute("src"));
        add(img.getAttribute("data-src"));
        srcset.split(",").forEach((source) => add(source.trim().split(/\s+/)[0]));
        if (!candidates.length) return;
        const sourceURL = candidates.find((candidate) => {
          try { return new URL(candidate).hostname.toLowerCase().includes("substack-post-media"); }
          catch (_) { return false; }
        }) || candidates[0];
        if (seen.has(sourceURL)) return;
        seen.add(sourceURL);
        images.push({sourceURL, candidates});
      });
      return images;
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
    const requiredImages = bodyImages();
    let loadedImages = 0;
    let failedImages = 0;
    const failedImageURLs = [];
    let cursor = 0;
    const workers = Array.from({length: Math.min(8, Math.max(1, requiredImages.length))}, async () => {
      while (cursor < requiredImages.length && timeLeft() > 250) {
        const image = requiredImages[cursor++];
        let loaded = false;
        for (const candidate of image.candidates) {
          if (await loadBodyImage(candidate)) {
            loaded = true;
            break;
          }
        }
        if (loaded) loadedImages += 1;
        else {
          failedImages += 1;
          failedImageURLs.push(image.sourceURL);
        }
      }
    });
    await Promise.allSettled(workers);
    for (let index = cursor; index < requiredImages.length; index += 1) {
      failedImageURLs.push(requiredImages[index].sourceURL);
      failedImages += 1;
    }
    const encodedFailedURLs = encodeURIComponent(JSON.stringify(failedImageURLs));
    yield {
      msg: `body image capture required=${requiredImages.length} loaded=${loadedImages} failed=${failedImages} page=${location.href} failed_urls=${encodedFailedURLs}`,
      fontFaces, loadedFonts, failedFonts, scrollSteps
    };
  }
}
