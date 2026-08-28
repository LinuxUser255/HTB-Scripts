#!/usr/bin/env bash
#
# check_clock_sync.sh
# Checks system clock sync status on login and auto-corrects drift.
# Add a call to this script from ~/.bashrc or ~/.zshrc to run on every
# new shell/login.
# Usage:
# Run once with the permanent fix: AUTO_INSTALL_NTP=1 ./check_clock_sync.sh
# after that, has_ntp_client will find chrony and the manual-step fallback stops being needed.

set -euo pipefail

DRIFT_THRESHOLD_SECONDS=5

log() {
    echo "$1"
}

get_ntp_synced() {
    timedatectl show --property=NTPSynchronized --value
}

has_ntp_client() {
    systemctl list-unit-files 2>/dev/null | grep -q systemd-timesyncd || command -v chronyc &>/dev/null
}

restart_ntp_client() {
    if systemctl list-unit-files | grep -q systemd-timesyncd; then
        sudo systemctl restart systemd-timesyncd
    elif command -v chronyc &>/dev/null; then
        sudo chronyc makestep
    else
        return 1
    fi
}

install_ntp_client() {
    if ! command -v apt &>/dev/null; then
        log "[!] apt not available — install an NTP client manually."
        return 1
    fi
    log "[*] Installing chrony..."
    sudo apt update -qq && sudo apt install -y chrony
    sudo systemctl enable --now chronyd 2>/dev/null || sudo systemctl enable --now chrony
}

check_and_fix_sync_flag() {
    local synced
    synced=$(get_ntp_synced)

    if [[ "$synced" == "yes" ]]; then
        log "[+] Clock already synchronized."
        return 0
    fi

    log "[!] Clock not synchronized (NTPSynchronized=$synced). Attempting fix..."
    restart_ntp_client || true

    sleep 2
    local resynced
    resynced=$(get_ntp_synced)
    if [[ "$resynced" == "yes" ]]; then
        log "[+] Clock resynced successfully."
    else
        log "[!] Still not synced — check 'timedatectl status' manually."
    fi
}

get_remote_epoch() {
    local remote_date remote_epoch
    remote_date=$(curl -s --max-time 3 --head http://google.com 2>/dev/null | grep -i ^date: || true)

    if [[ -z "$remote_date" ]]; then
        return 1
    fi

    remote_epoch=$(date -u -d "${remote_date#*: }" +%s 2>/dev/null || echo "")
    if [[ -z "$remote_epoch" ]]; then
        return 1
    fi

    echo "$remote_epoch"
}

manual_step_clock() {
    local remote_epoch="$1"
    log "[!] No NTP client available — manually stepping clock from HTTP Date header."
    log "    (Approximate: +/- a second or two of latency skew.)"
    sudo date -u -s "@${remote_epoch}" >/dev/null
    log "[+] Clock manually set to $(date -u)."
}

check_drift_against_remote() {
    local local_epoch remote_epoch diff abs_diff

    local_epoch=$(date -u +%s)

    if ! remote_epoch=$(get_remote_epoch); then
        log "[*] (Skipped remote time check — no network or curl unavailable)"
        return 0
    fi

    diff=$(( local_epoch - remote_epoch ))
    abs_diff=${diff#-}
    log "[*] Offset vs. remote reference: ${diff}s"

    if (( abs_diff > DRIFT_THRESHOLD_SECONDS )); then
        log "[!] Offset exceeds threshold (${DRIFT_THRESHOLD_SECONDS}s), forcing hard resync..."
        if has_ntp_client; then
            restart_ntp_client || true
        else
            manual_step_clock "$remote_epoch"
            if [[ "${AUTO_INSTALL_NTP:-0}" == "1" ]]; then
                install_ntp_client || true
            else
                log "[*] Tip: run with AUTO_INSTALL_NTP=1 to install chrony permanently."
            fi
        fi
    fi
}

main() {
    log "[*] Checking system clock sync status..."
    check_and_fix_sync_flag
    check_drift_against_remote
}

main "$@"
