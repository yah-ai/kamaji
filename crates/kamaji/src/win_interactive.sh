#!/bin/sh
# win-interactive — run ONE Windows command line inside the logged-on user's
# interactive desktop session instead of session 0 (R918-F8).
#
# kamaji is systemd-parented inside WSL, so everything it native-execs that
# crosses into Windows lands in session 0 and its non-interactive window
# station. A session-0 process cannot see, create or drive a session-1 window
# (EnumWindows is window-station scoped), so a GUI test there fails in a way
# that looks like the target is broken. This bridge hands the job to session 1
# through a one-shot scheduled task registered with /IT, waits for it, relays
# its output, and exits with its exit code. Task-scoped by design: nothing
# resident, nothing left behind, and an honest error when nobody is logged on.
#
# kamaji materializes this file and points $YAH_WIN_INTERACTIVE at it on WSL
# hosts only. Usage, from a native step:
#
#     "$YAH_WIN_INTERACTIVE" 'C:\Tools\pluginval.exe' --validate 'C:\x.vst3'
#
# The arguments are joined with single spaces into a Windows command line and
# written verbatim into a .bat, so Windows quoting is the caller's and `%` is
# expanded by cmd.exe. Output is relayed after the job ends, not live.
#
# Exit: the job's own code; 64 usage; 69 no interactive session (EX_UNAVAILABLE
# — the typed "nobody is logged on" answer); 70 the bridge itself failed;
# 143 terminated (the task is ended and deleted first).
#
# WHY THE FILE DANCE: kamaji runs under ProtectSystem=strict, which makes /mnt/c
# read-only in its mount namespace (measured on us-west-002, 2026-10-04). Every
# write to C: is therefore made by a WINDOWS process: the .bat is staged here,
# in kamaji's writable state dir, and copied onto C: by cmd.exe through the
# \\wsl.localhost path. Results are written by the task onto C: and only READ
# back through /mnt/c, which the read-only mount still allows. The job itself
# runs from local C:, not from the WSL share.

set -u

SYS32=${YAH_WIN_SYSTEM32:-/mnt/c/Windows/System32}
POLL=${YAH_WIN_INTERACTIVE_POLL:-1}
START_GRACE=${YAH_WIN_INTERACTIVE_START_GRACE:-30}

die() {
    code=$1
    shift
    echo "win-interactive: $*" >&2
    exit "$code"
}

[ "$#" -gt 0 ] || die 64 "usage: win-interactive <windows command line...>"
[ -x "$SYS32/cmd.exe" ] || die 70 "no Windows interop: $SYS32/cmd.exe is not executable (is this a WSL host?)"

# The interactive session. `query session` exits 1 even when it succeeds, so
# its status is not read; its rows are. A logged-on row has four fields —
# SESSIONNAME USERNAME ID STATE — and only `Active` has a live desktop: a
# `Disc` (disconnected RDP) session keeps its windows but renders nothing.
user=$("$SYS32/query.exe" session </dev/null 2>/dev/null | tr -d '\r' | awk '
    { sub(/^>/, "") }
    NF >= 4 && $4 == "Active" { print $2; exit }
')
[ -n "$user" ] || die 69 "no interactive session available: no Active user session in 'query session' (log on at the console or over RDP and retry)"

here=$(cd "$(dirname "$0")" && pwd) || die 70 "cannot resolve the bridge's own directory"
tag="yah-interactive-$$-$(date +%s)"
stage="$here/jobs/$tag"
mkdir -p "$stage" || die 70 "cannot create staging dir $stage"

win_dir="C:\\ProgramData\\yah\\interactive\\$tag"
lin_dir=$(dirname "$(dirname "$SYS32")")/ProgramData/yah/interactive/$tag

# cmd.exe drains its parent's stdin unless given /dev/null, and refuses a UNC
# working directory, so every call goes through this.
wcmd() {
    (cd / && "$SYS32/cmd.exe" /d /c "$@" </dev/null)
}

cleanup() {
    "$SYS32/schtasks.exe" /end /tn "$tag" </dev/null >/dev/null 2>&1
    "$SYS32/schtasks.exe" /delete /tn "$tag" /f </dev/null >/dev/null 2>&1
    wcmd rmdir /s /q "$win_dir" >/dev/null 2>&1
    rm -rf "$stage"
}
trap 'cleanup; exit 143' TERM INT HUP

# Prefix-redirect form throughout: `echo 0> f` would redirect fd 0.
{
    printf '@echo off\r\n'
    printf '>"%s\\started" echo started\r\n' "$win_dir"
    printf 'cd /d "%%USERPROFILE%%"\r\n'
    printf '%s >"%s\\stdout.log" 2>"%s\\stderr.log"\r\n' "$*" "$win_dir" "$win_dir"
    printf '>"%s\\exit.tmp" echo %%ERRORLEVEL%%\r\n' "$win_dir"
    printf 'move /y "%s\\exit.tmp" "%s\\exit" >nul\r\n' "$win_dir" "$win_dir"
} >"$stage/run.bat" || die 70 "cannot write $stage/run.bat"

stage_win=$(wslpath -w "$stage/run.bat") || die 70 "wslpath could not map $stage/run.bat"
wcmd mkdir "$win_dir" >/dev/null 2>&1
wcmd copy /y "$stage_win" "$win_dir\\run.bat" >/dev/null 2>&1
[ -f "$lin_dir/run.bat" ] || { cleanup; die 70 "staging $stage_win onto $win_dir failed"; }

# /tr must name a .bat: a quoted command line with arguments is rejected
# ("Invalid argument/option"). /sc once /st 00:00 is never reached; /run fires it.
if ! out=$("$SYS32/schtasks.exe" /create /tn "$tag" /tr "$win_dir\\run.bat" \
    /sc once /st 00:00 /rl limited /ru "$user" /it /f </dev/null 2>&1); then
    cleanup
    die 70 "schtasks /create as $user failed: $(printf '%s' "$out" | tr -d '\r')"
fi
if ! out=$("$SYS32/schtasks.exe" /run /tn "$tag" </dev/null 2>&1); then
    cleanup
    die 70 "schtasks /run failed: $(printf '%s' "$out" | tr -d '\r')"
fi

waited=0
while [ ! -f "$lin_dir/exit" ]; do
    if [ ! -f "$lin_dir/started" ] && [ "$waited" -ge "$START_GRACE" ]; then
        state=$("$SYS32/schtasks.exe" /query /tn "$tag" /fo list /v </dev/null 2>&1 | tr -d '\r' \
            | grep -E '^(Status|Last Result|Logon Mode):')
        cleanup
        die 70 "task $tag never started in session of $user after ${START_GRACE}s: $state"
    fi
    sleep "$POLL"
    waited=$((waited + POLL))
done

tr -d '\r' <"$lin_dir/stdout.log" 2>/dev/null
tr -d '\r' <"$lin_dir/stderr.log" >&2 2>/dev/null
code=$(tr -dc '0-9-' <"$lin_dir/exit")
cleanup
[ -n "$code" ] || die 70 "task $tag wrote an empty exit code"
# A Windows exit code is 32 bits; a POSIX one is 8. Anything that would wrap to
# 0 is reported as a failure rather than silently passing.
if [ "$code" -ne 0 ] && [ $((code & 255)) -eq 0 ]; then
    echo "win-interactive: job exited $code, which does not fit an exit status" >&2
    exit 1
fi
exit $((code & 255))
