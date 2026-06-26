FROM webrecorder/browsertrix-crawler:1.13.1

COPY docker/browsertrix-worker/worker.sh /usr/local/bin/warcdriver-browsertrix-worker
COPY docker/browsertrix-worker/cookie-profile.mjs /app/warcdriver-cookie-profile.mjs
COPY docker/browsertrix-worker/behaviors /app/warcdriver-behaviors
RUN chmod 0755 /usr/local/bin/warcdriver-browsertrix-worker /app/warcdriver-cookie-profile.mjs \
  && find /app/warcdriver-behaviors -type f -exec chmod 0644 {} \;

ENTRYPOINT ["/usr/local/bin/warcdriver-browsertrix-worker"]
