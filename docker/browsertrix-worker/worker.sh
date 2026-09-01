#!/bin/sh
set -eu

QUEUE_DIR="${BROWSERTRIX_QUEUE_DIR:-/data/browsertrix/jobs}"
RUNS_DIR="${BROWSERTRIX_RUNS_DIR:-/data/browsertrix/runs}"
POLL_INTERVAL="${BROWSERTRIX_POLL_INTERVAL:-1}"
GRACE_SECONDS="${BROWSERTRIX_CANCEL_GRACE_SECONDS:-30}"
SUBSTACK_BACKOFF_BASE="${SUBSTACK_BACKOFF_BASE:-60}"
SUBSTACK_BACKOFF_MAX="${SUBSTACK_BACKOFF_MAX:-300}"
SUBSTACK_BACKOFF_DECAY_PAGES="${SUBSTACK_BACKOFF_DECAY_PAGES:-10}"

mkdir -p "$QUEUE_DIR" "$RUNS_DIR"
echo "warcdriver Browsertrix worker listening: queue=$QUEUE_DIR runs=$RUNS_DIR"

json_time() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

write_done() {
  job_dir="$1"
  status="$2"
  code="$3"
  tmp="$job_dir/done.json.tmp"
  printf '{"status":"%s","exitCode":%s,"finishedAt":"%s"}\n' "$status" "$code" "$(json_time)" > "$tmp"
  mv "$tmp" "$job_dir/done.json"
}

run_job() {
  job_dir="$1"
  config="$job_dir/config.json"
  log="$job_dir/browsertrix.log"

  printf '{"timestamp":"%s","logLevel":"info","context":"worker","message":"WARCdriver Browsertrix worker claimed job","details":{}}\n' "$(json_time)" >> "$log"

  if [ -f "$job_dir/cookies.json" ]; then
    set +e
    node /app/warcdriver-cookie-profile.mjs "$job_dir/cookies.json" "$job_dir/cookie-profile.tar.gz" >> "$log" 2>&1
    cookie_code="$?"
    set -e
    if [ "$cookie_code" -ne 0 ]; then
      write_done "$job_dir" "failed" "$cookie_code"
      rm -f "$job_dir/running"
      return
    fi
  fi

  /usr/bin/crawl --config "$config" --cwd "$RUNS_DIR" >> "$log" 2>&1 &
  pid="$!"
  status="succeeded"
  code=0
  collection="$(jq -r '.collection // empty' "$config")"
  pages_file="$RUNS_DIR/collections/$collection/pages/pages.jsonl"
  seen_page_lines=0
  throttle_level=0
  successes_since_throttle=0

  while kill -0 "$pid" 2>/dev/null; do
    if [ -f "$job_dir/cancel" ]; then
      status="canceled"
      printf '{"timestamp":"%s","logLevel":"warn","context":"worker","message":"Cancellation requested; sending SIGINT to Browsertrix","details":{}}\n' "$(json_time)" >> "$log"
      kill -INT "$pid" 2>/dev/null || true
      waited=0
      while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$GRACE_SECONDS" ]; do
        sleep 1
        waited=$((waited + 1))
      done
      if kill -0 "$pid" 2>/dev/null; then
        printf '{"timestamp":"%s","logLevel":"warn","context":"worker","message":"Browsertrix did not stop gracefully; sending SIGTERM","details":{}}\n' "$(json_time)" >> "$log"
        kill -TERM "$pid" 2>/dev/null || true
      fi
      break
    fi

    if [ -f "$job_dir/substack-mode" ] && [ -f "$pages_file" ]; then
      page_lines="$(wc -l < "$pages_file" | tr -d ' ')"
      if [ "$page_lines" -gt "$seen_page_lines" ]; then
        new_statuses="$(sed -n "$((seen_page_lines + 1)),${page_lines}p" "$pages_file" | jq -r 'select(.url != null) | .status // 0')"
        seen_page_lines="$page_lines"
        saw_rate_limit=0
        successful_pages=0
        for page_status in $new_statuses; do
          if [ "$page_status" = "429" ]; then
            saw_rate_limit=1
          elif [ "$page_status" -ge 200 ] && [ "$page_status" -lt 400 ]; then
            successful_pages=$((successful_pages + 1))
          fi
        done
        if [ "$saw_rate_limit" -eq 1 ]; then
          throttle_level=$((throttle_level + 1))
          delay="$SUBSTACK_BACKOFF_BASE"
          level=1
          while [ "$level" -lt "$throttle_level" ] && [ "$delay" -lt "$SUBSTACK_BACKOFF_MAX" ]; do
            delay=$((delay * 2))
            level=$((level + 1))
          done
          if [ "$delay" -gt "$SUBSTACK_BACKOFF_MAX" ]; then
            delay="$SUBSTACK_BACKOFF_MAX"
          fi
          successes_since_throttle=0
          printf '{"timestamp":"%s","logLevel":"warn","context":"worker","message":"Substack HTTP 429 detected; adaptive crawl cooldown for %s seconds (level %s)","details":{}}\n' "$(json_time)" "$delay" "$throttle_level" >> "$log"
          kill -STOP "$pid" 2>/dev/null || true
          waited=0
          while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$delay" ] && [ ! -f "$job_dir/cancel" ]; do
            sleep 1
            waited=$((waited + 1))
          done
          kill -CONT "$pid" 2>/dev/null || true
        elif [ "$successful_pages" -gt 0 ] && [ "$throttle_level" -gt 0 ]; then
          successes_since_throttle=$((successes_since_throttle + successful_pages))
          if [ "$successes_since_throttle" -ge "$SUBSTACK_BACKOFF_DECAY_PAGES" ]; then
            throttle_level=$((throttle_level - 1))
            successes_since_throttle=0
            printf '{"timestamp":"%s","logLevel":"info","context":"worker","message":"Substack adaptive cooldown decayed to level %s after sustained successful pages","details":{}}\n' "$(json_time)" "$throttle_level" >> "$log"
          fi
        fi
      fi
    fi
    sleep 1
  done

  set +e
  wait "$pid"
  code="$?"
  set -e
  if [ "$status" = "succeeded" ] && [ "$code" -ne 0 ]; then
    status="failed"
  fi
  write_done "$job_dir" "$status" "$code"
  rm -f "$job_dir/running"
}

while true; do
  found=0
  for job_dir in "$QUEUE_DIR"/*; do
    [ -d "$job_dir" ] || continue
    [ -f "$job_dir/queued" ] || continue
    if mv "$job_dir/queued" "$job_dir/running" 2>/dev/null; then
      found=1
      run_job "$job_dir"
    fi
  done
  if [ "$found" -eq 0 ]; then
    sleep "$POLL_INTERVAL"
  fi
done
