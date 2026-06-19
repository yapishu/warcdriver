FROM webrecorder/browsertrix-crawler:1.13.1

COPY docker/browsertrix-worker/worker.sh /usr/local/bin/warcdriver-browsertrix-worker
COPY docker/browsertrix-worker/cookie-profile.mjs /app/warcdriver-cookie-profile.mjs
RUN chmod 0755 /usr/local/bin/warcdriver-browsertrix-worker /app/warcdriver-cookie-profile.mjs

ENTRYPOINT ["/usr/local/bin/warcdriver-browsertrix-worker"]
