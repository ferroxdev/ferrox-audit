#!/usr/bin/env bash
# The warm build tree every worktree starts from, and the only way to write or
# repair a worktree's pointer at it. Sourced, not run.
#
# A worktree does not build into the seed itself: Cargo takes an exclusive lock
# on a target dir for the whole build, so a shared dir makes four agents queue.
# Instead each worktree gets a copy-on-write clone of the seed on first use.
# `debug/deps` and its fingerprints are path-independent, so the clone's
# dependencies stay fresh (a test binary links in under a second) while writes
# go to new blocks: separate lock, no race, and no second copy of the deps.
#
# A clean worktree whose source is byte-identical to the main checkout's goes
# further: its cloned dep-info is repointed at the worktree and its inputs are
# aged, so Cargo reuses the seed's compiled workspace crates too. A branch with
# edits in a crate leaves that crate's inputs at checkout time and rebuilds it;
# the paths are compared by tree hash, never assumed.

ferrox_shared_target() {
  local toplevel parent
  toplevel="$(git rev-parse --show-toplevel)"
  parent="$(cd "$toplevel/.." && pwd)"
  printf '%s\n' "$parent/.ferrox-target"
}

# The main checkout is the seed's only writer, so its HEAD is the source the
# seed's workspace artefacts belong to.
ferrox_main_worktree() {
  local dir
  while IFS= read -r dir; do
    [[ -d "$dir" ]] || continue
    if [[ "$(git -C "$dir" rev-parse --git-dir 2>/dev/null)" == \
          "$(git -C "$dir" rev-parse --git-common-dir 2>/dev/null)" ]]; then
      (cd "$dir" && pwd -P)
      return 0
    fi
  done < <(git worktree list --porcelain | sed -n 's/^worktree //p')
  return 1
}

# What the seed's compiled crates depend on. The tools are left out on purpose:
# `ferrox-prompt` and `ferrox-bench` embed CARGO_MANIFEST_DIR, so they must run
# from the worktree even when their bytes match the seed's.
ferrox_reuse_paths() {
  printf '%s\n' crates/ferrox-core crates/ferrox-app scripts Cargo.toml Cargo.lock
}

ferrox_reuse_paths_clean() {
  local path="$1" rel
  while IFS= read -r rel; do
    [[ -z "$(git -C "$path" status --porcelain --untracked-files=all -- "$rel" 2>/dev/null)" ]] || return 1
  done < <(ferrox_reuse_paths)
}

# The caller has established that both sides are clean, so the index's tree hash
# is the content hash: equal trees compile to the same artefacts.
ferrox_reuse_path_same() {
  local dest="$1" main="$2" rel="$3"
  [[ "$(git -C "$dest" rev-parse "HEAD:$rel" 2>/dev/null)" == \
     "$(git -C "$main" rev-parse "HEAD:$rel" 2>/dev/null)" ]]
}

# Cargo's own freshness check is the gate: a no-op test build costs a fraction
# of a second, and a stale one is a build the worktree would have paid anyway.
ferrox_refresh_seed() {
  local main="$1" shared="$2" log
  ferrox_write_cargo_config "$main" "$shared"
  log="$(mktemp "${TMPDIR:-/tmp}/ferrox-seed.XXXXXX")"
  if ! ( cd "$main" && CARGO_INCREMENTAL=0 cargo test --workspace --locked --no-run \
          --message-format=json >"$log" 2>&1 ); then
    rm -f "$log"
    return 1
  fi
  if grep -q '"fresh":false' "$log"; then
    echo "seed: refreshed the main checkout's workspace artefacts" >&2
  fi
  rm -f "$log"
}

# A target cloned from the seed still names the seed's source paths; one that
# has built in the worktree names its own.
ferrox_depinfo_names() {
  local target="$1" main="$2"
  grep -aFlq -- "$main/crates/" "$target"/debug/.fingerprint/*/dep-* 2>/dev/null
}

ferrox_touch_path() {
  local dest="$1" rel="$2" stamp="$3" files
  files="$(git -C "$dest" ls-files -- "$rel" 2>/dev/null)"
  [[ -n "$files" ]] || return 0
  if [[ -n "$stamp" ]]; then
    git -C "$dest" ls-files -z -- "$rel" | ( cd "$dest" && xargs -0 touch -t "$stamp" )
  else
    git -C "$dest" ls-files -z -- "$rel" | ( cd "$dest" && xargs -0 touch )
  fi
}

# Point the clone's dep-info at the worktree and age the inputs whose content is
# main's. Inputs that differ stay newer than the dep-info, so Cargo rebuilds
# exactly those crates and their dependants.
ferrox_adopt_seed_inputs() {
  local dest="$1" shared="$2" main rewritten rel
  main="$(ferrox_main_worktree)" || return 1
  [[ ! "$dest" -ef "$main" ]] || return 1
  ferrox_target_is_shared "$main" "$shared" || return 1
  ferrox_depinfo_names "$dest/target" "$main" || return 1
  ferrox_reuse_paths_clean "$main" || return 1
  ferrox_reuse_paths_clean "$dest" || return 1
  rewritten="$(python3 "$(dirname "${BASH_SOURCE[0]}")/rewrite-depinfo.py" \
    "$main" "$dest" "$dest/target" 2>/dev/null)" || return 1
  # A stream this cargo does not know stays named after the seed: do not age a
  # unit whose inputs still point somewhere else.
  ferrox_depinfo_names "$dest/target" "$main" && return 1
  while IFS= read -r rel; do
    if ferrox_reuse_path_same "$dest" "$main" "$rel"; then
      ferrox_touch_path "$dest" "$rel" 202001010000
    else
      ferrox_touch_path "$dest" "$rel" ""
    fi
  done < <(ferrox_reuse_paths)
  ferrox_touch_path "$dest" crates/ferrox-prompt ""
  ferrox_touch_path "$dest" crates/ferrox-bench ""
  printf 'seed: workspace artefacts reused (%s dep-info file(s) repointed)\n' "$rewritten"
}

# Adoption failed, so the clone's fingerprints are newer than the worktree's
# checkout. Age every workspace input past them or Cargo may reuse the seed's
# objects for source this worktree does not have.
ferrox_invalidate_seed_inputs() {
  local dest="$1" rel
  while IFS= read -r rel; do
    ferrox_touch_path "$dest" "$rel" ""
  done < <(ferrox_reuse_paths)
  ferrox_touch_path "$dest" crates/ferrox-prompt ""
  ferrox_touch_path "$dest" crates/ferrox-bench ""
}

# Probe before pointing anything at it: a root-owned seed (one sudo'd build is
# enough) fails every cargo call, and the private dir that follows looks like a
# choice rather than a write failure.
# One writer at a time across worktrees: claiming and reclaiming both move
# directories under the shared tree, and two of them interleaving can delete a
# clone another process just created.
# The lock lives beside the seed, not inside it: adopting a main-checkout target
# replaces the seed directory, and a lock in there would disappear with it.
ferrox_lock_path() {
  printf '%s.lock\n' "$1"
}

# A process holding an flock on the lock file is the lock. The kernel releases
# it on exit, and the holder exits when its parent disappears, so stale-lock
# recovery needs no PID file and no remove.
ferrox_lock_acquire() {
  local shared="$1" lock ready status waited=0
  lock="$(ferrox_lock_path "$shared")"
  mkdir -p "$(dirname "$lock")" || return 1
  ready="$(mktemp "${TMPDIR:-/tmp}/ferrox-lock.XXXXXX")" || return 1
  python3 - "$lock" "$ready" <<'PY' >/dev/null 2>&1 &
import fcntl
import os
import sys
import time

path, ready = sys.argv[1], sys.argv[2]
parent = os.getppid()


def report(value):
    with open(ready, "w", encoding="utf-8") as handle:
        handle.write(value)


try:
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o644)
    deadline = time.monotonic() + 300
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            if os.getppid() != parent:
                os._exit(1)
            if time.monotonic() >= deadline:
                report("timeout")
                os._exit(1)
            time.sleep(0.1)
    report("ok")
    while os.getppid() == parent:
        time.sleep(0.2)
    os.close(fd)
except OSError:
    report("error")
    os._exit(1)
PY
  _FERROX_LOCK_PID=$!
  while [[ ! -s "$ready" ]]; do
    if ! kill -0 "$_FERROX_LOCK_PID" 2>/dev/null; then
      rm -f "$ready"
      _FERROX_LOCK_PID=""
      echo "::error::could not acquire $lock" >&2
      return 1
    fi
    sleep 0.05
    waited=$((waited + 1))
    if (( waited >= 6000 )); then
      kill "$_FERROX_LOCK_PID" 2>/dev/null || true
      wait "$_FERROX_LOCK_PID" 2>/dev/null || true
      rm -f "$ready"
      _FERROX_LOCK_PID=""
      echo "::error::timed out waiting for $lock" >&2
      return 1
    fi
  done
  status="$(cat "$ready")"
  rm -f "$ready"
  if [[ "$status" != ok ]]; then
    kill "$_FERROX_LOCK_PID" 2>/dev/null || true
    wait "$_FERROX_LOCK_PID" 2>/dev/null || true
    _FERROX_LOCK_PID=""
    echo "::error::could not acquire $lock ($status)" >&2
    return 1
  fi
}

ferrox_lock_release() {
  local pid="${_FERROX_LOCK_PID:-}"
  [[ -n "$pid" ]] || return 0
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  _FERROX_LOCK_PID=""
}

# Cargo holds its per-target lock for the whole build, so an open descriptor is
# the witness that a target is live even when no file changed in the age window.
# Without lsof or fuser, 2 says "unknown": cleanup must skip, not assume idle.
ferrox_target_in_use() {
  local target="$1" profile
  [[ -n "$target" ]] || return 2
  [[ -d "$target" ]] || return 1
  local -a locks=()
  for profile in debug release doc; do
    locks+=("$target/$profile/.cargo-lock" "$target/$profile/.cargo-build-lock")
  done
  locks+=("$target/.cargo-lock")
  if command -v lsof >/dev/null; then
    local holders status=0
    holders="$(lsof -t "${locks[@]}" 2>/dev/null)" || status=$?
    [[ -z "$holders" ]] || return 0
    if [[ "$status" -eq 1 ]]; then
      return 1
    fi
    return 2
  fi
  if command -v fuser >/dev/null; then
    fuser -s "${locks[@]}" >/dev/null 2>&1
    return
  fi
  return 2
}

# Only a positive idle probe may be reclaimed; an unknown probe is not idle.
ferrox_target_idle() {
  local status=0
  ferrox_target_in_use "$1" || status=$?
  [[ "$status" -eq 1 ]]
}

# A partial lsof match still lists its holders; only an empty, status-1 probe is idle.
ferrox_target_probe_selftest() {
  local tmp fake target rc
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/ferrox-probe.XXXXXX")"
  target="$tmp/target"
  fake="$tmp/bin/lsof"
  mkdir -p "$target/debug" "$tmp/bin"
  : >"$target/debug/.cargo-lock"
  printf '#!/bin/sh\nprintf "%%s\\n" 123\nexit 1\n' >"$fake"
  chmod +x "$fake"
  rc=0
  PATH="$tmp/bin:$PATH" ferrox_target_in_use "$target" || rc=$?
  [[ "$rc" -eq 0 ]] || { rm -rf "$tmp"; echo "probe selftest: lsof holder with status 1 read as not busy" >&2; return 1; }
  printf '#!/bin/sh\nexit 1\n' >"$fake"
  rc=0
  PATH="$tmp/bin:$PATH" ferrox_target_in_use "$target" || rc=$?
  [[ "$rc" -eq 1 ]] || { rm -rf "$tmp"; echo "probe selftest: empty status-1 lsof read as not idle" >&2; return 1; }
  printf '#!/bin/sh\nexit 2\n' >"$fake"
  rc=0
  PATH="$tmp/bin:$PATH" ferrox_target_in_use "$target" || rc=$?
  [[ "$rc" -eq 2 ]] || { rm -rf "$tmp"; echo "probe selftest: failed lsof read as known" >&2; return 1; }
  rc=0
  ferrox_target_in_use "" || rc=$?
  [[ "$rc" -eq 2 ]] || { rm -rf "$tmp"; echo "probe selftest: absent target read as known" >&2; return 1; }
  rm -rf "$tmp"
  echo "probe selftest: ok"
}

# Reserve Cargo's own locks before a reclaimer moves a target aside. The holder
# is a process, so a build starting after the probe either waits on these locks
# or finds the target gone; the inode a build waits on stays inside the moved
# tree while it is deleted.
ferrox_target_reserve() {
  local target="$1" ready status waited=0
  [[ -d "$target" ]] || return 1
  ready="$(mktemp "${TMPDIR:-/tmp}/ferrox-reserve.XXXXXX")" || return 1
  python3 - "$target" "$ready" <<'PY' >/dev/null 2>&1 &
import fcntl
import os
import sys
import time

target, ready = sys.argv[1], sys.argv[2]


def report(value):
    with open(ready, "w", encoding="utf-8") as handle:
        handle.write(value)


fds = []
try:
    for part in ("", "debug", "release", "doc"):
        directory = os.path.join(target, part) if part else target
        os.makedirs(directory, exist_ok=True)
        for name in (".cargo-lock", ".cargo-build-lock"):
            fd = os.open(os.path.join(directory, name), os.O_CREAT | os.O_RDWR, 0o644)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fds.append(fd)
except OSError:
    for fd in fds:
        os.close(fd)
    report("busy")
    os._exit(1)
report("ok")
parent = os.getppid()
while os.getppid() == parent:
    time.sleep(0.2)
for fd in fds:
    os.close(fd)
PY
  _FERROX_RESERVE_PID=$!
  while [[ ! -s "$ready" ]]; do
    if ! kill -0 "$_FERROX_RESERVE_PID" 2>/dev/null; then
      rm -f "$ready"
      _FERROX_RESERVE_PID=""
      return 1
    fi
    sleep 0.05
    waited=$((waited + 1))
    if (( waited >= 200 )); then
      kill "$_FERROX_RESERVE_PID" 2>/dev/null || true
      wait "$_FERROX_RESERVE_PID" 2>/dev/null || true
      rm -f "$ready"
      _FERROX_RESERVE_PID=""
      return 1
    fi
  done
  status="$(cat "$ready")"
  rm -f "$ready"
  if [[ "$status" != ok ]]; then
    kill "$_FERROX_RESERVE_PID" 2>/dev/null || true
    wait "$_FERROX_RESERVE_PID" 2>/dev/null || true
    _FERROX_RESERVE_PID=""
    return 1
  fi
}

ferrox_target_unreserve() {
  local pid="${_FERROX_RESERVE_PID:-}"
  [[ -n "$pid" ]] || return 0
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  _FERROX_RESERVE_PID=""
}

ferrox_claim_is_live() {
  local staging="$1" owner
  owner="$(awk 'NR == 1 {print $1}' "$staging/.ferrox-claim" 2>/dev/null)"
  [[ -n "$owner" ]] && kill -0 "$owner" 2>/dev/null
}

ferrox_require_shared_writable() {
  local shared="$1" probe
  probe="$shared/.write-probe"
  mkdir -p "$shared" || {
    echo "::error::cannot create $shared" >&2
    return 1
  }
  if ! : >"$probe" 2>/dev/null; then
    rm -f "$probe" 2>/dev/null
    echo "::error::$shared is not writable by $(id -un): sudo chown -R $(id -un) $(id -gn) $shared" >&2
    return 1
  fi
  rm -f "$probe"
}

# One canonical config, symlinked into every worktree: the bytes are identical
# for every branch, and a single file cannot drift the way a patch of copies
# does. No target-dir here, so `target/` is whatever the worktree owns; the
# rustflags are ci.yml's, so a hand-run `cargo test` shares the gate's
# fingerprints instead of rebuilding the world beside it.
ferrox_cargo_config_path() {
  local shared="$1"
  printf '%s\n' "$shared/cargo-config.toml"
}

ferrox_cargo_config_text() {
  echo "# Generated by scripts/new-worktree.sh / scripts/claim-target.sh. Never committed:"
  echo "# every worktree clones the warm tree here, so dependencies compile once."
  echo ""
  echo "[build]"
  echo "# CI's flags, kept identical so a plain cargo call reuses its artifacts."
  echo "rustflags = [\"-D\", \"warnings\", \"--cfg\", \"aes_armv8\", \"--cfg\", \"polyval_armv8\"]"
  echo ""
  echo "# Hardware crypto for aarch64 builds, matching ci.yml so a local"
  echo "# measurement is of the code CI ships: the aes and polyval crates"
  echo "# (behind aes-gcm, i.e. every VMess header seal, AES data frame,"
  echo "# auth-id block and Shadowsocks chunk) compile their ARMv8-Crypto"
  echo "# backends only behind these cfgs and then runtime-dispatch, so a"
  echo "# device without the extension runs the soft code it runs today."
  echo "# Measured 12x on a VMess header seal and on a Cipher::Aes data frame."
  echo "# x86_64 consults neither cfg."
  echo "[target.aarch64-apple-darwin]"
  echo "rustflags = [\"-D\", \"warnings\", \"--cfg\", \"aes_armv8\", \"--cfg\", \"polyval_armv8\"]"
  echo ""
  echo "[target.aarch64-unknown-linux-gnu]"
  echo "rustflags = [\"-D\", \"warnings\", \"--cfg\", \"aes_armv8\", \"--cfg\", \"polyval_armv8\"]"
}

ferrox_write_cargo_config() {
  local dest="$1" shared="$2" config tmp
  config="$(ferrox_cargo_config_path "$shared")"
  mkdir -p "$dest/.cargo" "$shared"
  tmp="$(mktemp "$shared/.cargo-config.XXXXXX")"
  ferrox_cargo_config_text > "$tmp"
  # Read-only, so a checkout still running the pre-clone scripts cannot clobber
  # the one config through the symlink with a `target-dir` that rebuilds the
  # queue. Replacing the inode needs only the directory, so this script can.
  chmod 444 "$tmp"
  mv -f "$tmp" "$config"

  rm -f "$dest/.cargo/config.toml" "$dest/.cargo/config"
  ln -s "$config" "$dest/.cargo/config.toml"
}

# APFS clonefile shares blocks until one side writes; reflink is the Linux
# equivalent. A filesystem with neither pays a real copy once, not the lock.
ferrox_clone_dir() {
  local src="$1" dest="$2"
  rm -rf "$dest"
  if cp -cR "$src" "$dest" 2>/dev/null; then
    return 0
  fi
  rm -rf "$dest"
  if cp --reflink=auto -R "$src" "$dest" 2>/dev/null; then
    return 0
  fi
  rm -rf "$dest"
  cp -R "$src" "$dest"
}

# The seed is itself whatever the main worktree last built; a clone carries only
# the profiles locals use, and drops incremental state (its sessions name the
# seed's source paths, so they can never hit here). A worktree tests in debug;
# release and doc are a click away in Cargo and would otherwise be a gigabyte of
# copy-on-write blocks every branch pays for. `FERROX_TARGET_PROFILES` widens it
# for a branch that really does measure release locally.
ferrox_target_profiles() {
  local part profiles="${FERROX_TARGET_PROFILES:-debug}"
  local -a parts
  profiles="${profiles//$'\n'/ }"
  read -ra parts <<< "$profiles"
  for part in "${parts[@]}"; do
    case "$part" in
      debug|release|doc) printf '%s\n' "$part" ;;
      *) echo "::error::FERROX_TARGET_PROFILES: unknown profile '$part'" >&2; return 1 ;;
    esac
  done
}

ferrox_clone_target() {
  local dest="$1" shared="$2" part
  local staging="$dest/target.claim"
  local profiles
  local -a parts
  profiles="$(ferrox_target_profiles)" || return 1
  profiles="${profiles//$'\n'/ }"
  read -ra parts <<< "$profiles"
  rm -rf "$staging"
  mkdir -p "$staging"
  for part in "${parts[@]}"; do
    [[ -d "$shared/$part" ]] || continue
    ferrox_clone_dir "$shared/$part" "$staging/$part"
  done
  if [[ -f "$shared/.rustc_info.json" ]]; then
    cp "$shared/.rustc_info.json" "$staging/.rustc_info.json"
  fi
  if [[ -f "$shared/CACHEDIR.TAG" ]]; then
    cp "$shared/CACHEDIR.TAG" "$staging/CACHEDIR.TAG"
  fi
  rm -rf "$staging/debug/incremental" "$staging/release/incremental"
  rm -f "$staging"/debug/.cargo-*lock "$staging"/release/.cargo-*lock
  printf '%s\n' "$$" > "$staging/.ferrox-claim"
  # A half-copied target must never read as claimed: replace `target` only once
  # the clone is complete.
  rm -rf "$dest/target"
  mv "$staging" "$dest/target"
}

# A checkout still running the pre-clone scripts parks a real target in
# `aside/` and points the worktree back at the seed. Sealing the door makes that
# repair fail at the move instead, leaving the clone isolated; new code never
# writes there, so this costs nothing once every worktree has rebased.
ferrox_seal_aside() {
  local shared="$1"
  mkdir -p "$shared/aside"
  chmod 555 "$shared/aside"
}

# A worktree is isolated when it owns a real target directory. A symlink to the
# seed is not: Cargo would follow it and take the seed's lock, which is exactly
# the queue this avoids. A first claim clones; later calls are a single test.
ferrox_target_is_shared() {
  local dest="$1" shared="$2"
  [[ -L "$dest/target" && "$dest/target" -ef "$shared" ]]
}

ferrox_target_is_own() {
  local dest="$1"
  [[ -d "$dest/target" && ! -L "$dest/target" ]]
}

ferrox_claim_target() {
  local dest="$1" shared="$2" main fresh=0
  ferrox_seal_aside "$shared"
  if ferrox_target_is_own "$dest"; then
    return 0
  fi
  ferrox_lock_acquire "$shared" || return 1
  if ferrox_target_is_own "$dest"; then
    ferrox_lock_release "$shared"
    return 0
  fi
  # Refresh the seed before the clone, so the clone carries the fresh artefacts
  # rather than the ones the refresh would have replaced. Adoption is only safe
  # when the clone was taken after a successful refresh.
  if main="$(ferrox_main_worktree)" &&
      [[ ! "$dest" -ef "$main" ]] &&
      ferrox_target_is_shared "$main" "$shared" &&
      ferrox_reuse_paths_clean "$main" &&
      ferrox_reuse_paths_clean "$dest" &&
      ferrox_refresh_seed "$main" "$shared"; then
    fresh=1
  fi
  ferrox_clone_target "$dest" "$shared"
  if [[ "$fresh" != 1 ]] || ! ferrox_adopt_seed_inputs "$dest" "$shared"; then
    ferrox_invalidate_seed_inputs "$dest"
  fi
  ferrox_lock_release "$shared"
}

ferrox_config_is_shared() {
  local dest="$1" shared="$2" config
  config="$(ferrox_cargo_config_path "$shared")"
  [[ -e "$dest/.cargo/config.toml" && "$dest/.cargo/config.toml" -ef "$config" ]] || return 1
  cmp -s <(ferrox_cargo_config_text) "$config"
}

# Every pinned checkout is a symlink to the one copy this machine fetched: a
# second clone per worktree is the same reading material bought again. Existing
# real checkouts are left alone; fetch-upstream.sh decides their pin.
ferrox_link_upstream() {
  local dest="$1" top="$2" linked=0 checkout base_name
  mkdir -p "$dest/upstream"
  for checkout in "$top"/upstream/*/; do
    checkout="${checkout%/}"
    base_name="$(basename "$checkout")"
    [[ -d "$checkout/.git" ]] || continue
    if [[ -L "$dest/upstream/$base_name" ]]; then
      if [[ "$dest/upstream/$base_name" -ef "$checkout" ]]; then
        continue
      fi
      rm "$dest/upstream/$base_name"
    elif [[ -e "$dest/upstream/$base_name" ]]; then
      continue
    fi
    ln -s "$checkout" "$dest/upstream/$base_name"
    linked=$((linked + 1))
  done
  printf '%s\n' "$linked"
}

ferrox_link_worktree() {
  local dest="$1" top="$2" shared="$3"
  ferrox_write_cargo_config "$dest" "$shared"
  ferrox_claim_target "$dest" "$shared"
  ferrox_link_upstream "$dest" "$top" >/dev/null
}
