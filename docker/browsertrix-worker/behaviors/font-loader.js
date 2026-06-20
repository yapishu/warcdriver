class WARCdriverFontLoader {
  static id = "WARCdriver Remote Font Loader";
  static runInIframe = true;

  static init() {
    return {};
  }

  static isMatch() {
    return typeof document !== "undefined" && Boolean(document.fonts);
  }

  async* run(ctx) {
    const sleep = ctx?.Lib?.sleep || ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    const startedAt = Date.now();
    const maxMs = 8000;
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
    yield {msg: "remote font load complete", fontFaces, loadedFonts, failedFonts, scrollSteps};
  }
}
