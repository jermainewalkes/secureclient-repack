#!/bin/bash
#
# secureclient-repack.sh
# Cisco Secure Client (macOS) — repackage and sign the predeploy pkg
#
#   1. Finds the Secure Client predeploy DMG (menu if more than one)
#   2. Lets you choose which modules to KEEP (VPN core and GUI are pinned)
#   3. FULL strip: removes each dropped module's choice, pkg-refs AND payload
#      folder together, so the pkg only advertises the kept modules
#      (clean module list in your MDM, smaller file)
#   4. Re-flattens and signs with a "Developer ID Installer" identity
#   5. If Umbrella is kept, sources OrgInfo.json and emits a ready-to-deploy
#      root shell script that drops it on the endpoint
#
# Interactive by default; every step can also be driven by flags for
# scripted use. Run ./secureclient-repack.sh --help for details.
#
# Stock macOS tools only (bash 3.2 safe): hdiutil pkgutil productsign security
# awk find xsltproc plutil. Run on the machine holding the DMG and the cert.
#
# This project is not affiliated with, endorsed by or supported by Cisco
# Systems, Inc. Cisco Secure Client is a trademark of Cisco Systems, Inc.
# You must supply your own licensed Cisco Secure Client predeploy package;
# this tool does not download or redistribute any Cisco software.
#
# Copyright (c) 2026 Jermaine Walkes
# Released under the MIT licence — see the LICENSE file.
#

# Strict mode applies when executed; skipped when sourced by the test suite
# so the harness shell keeps its own options.
if [[ -z "${SECURECLIENT_REPACK_TEST:-}" ]]; then
  set -euo pipefail
fi

VERSION="1.1.1"

# ---------- helpers -----------------------------------------------------------
lower(){ printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
die(){ echo "ERROR: $*" >&2; exit 1; }

# "gui" and "ui" are matched as whole words only: as bare substrings they also
# match anything merely containing them — build, suite, requirements, guided —
# which would then be labelled as the UI shell and impossible to drop.
is_ui_module(){ [[ "$(lower "$1")" =~ (^|[^a-z0-9])(gui|ui)([^a-z0-9]|$) ]]; }

# The base client cannot run without the VPN core or the GUI shell.
is_pinned(){
  local lc; lc="$(lower "$1")"
  if [[ "$lc" == *vpn* ]]; then return 0; fi
  is_ui_module "$lc"
}

# Payload folder names come from the package's own Distribution. Anything other
# than a plain folder name (traversal, absolute path, leading dash) must never
# reach the rm -rf that deletes orphaned payloads.
validate_payload_name(){
  case "$1" in
    ''|.|..)     die "Refusing an empty or relative payload path from the package: '$1'";;
    */*|*..*|-*) die "Refusing an unsafe payload path from the package: '$1'";;
  esac
}

friendly(){
  local lc; lc="$(lower "$1")"
  if [[ "$lc" != *vpn* ]] && is_ui_module "$lc"; then
    echo "GUI / UI shell (pinned)"; return 0
  fi
  case "$lc" in
    *vpn*)                          echo "VPN — Core & AnyConnect (base client, pinned)";;
    *umbrella*)                     echo "Umbrella Roaming Security";;
    *dart*)                         echo "DART — Diagnostics & Reporting";;
    *iseposture*|*ise_posture*)     echo "ISE Posture";;
    *nvm*|*networkvisibility*)      echo "Network Visibility Module";;
    *thousandeyes*)                 echo "ThousandEyes Endpoint Agent";;
    *zta*|*zerotrust*)              echo "Zero Trust Access";;
    *firewallposture*|*hostscan*|*secfirewall*) echo "Secure Firewall Posture";;
    *posture*)                      echo "Posture";;
    *fireamp*|*secureendpoint*|*amp*) echo "AMP Enabler / Secure Endpoint";;
    *websecurity*)                  echo "Web Security (deprecated)";;
    *nam*|*networkaccess*)          echo "Network Access Manager";;
    *sbl*|*startbeforelogin*)       echo "Start Before Login";;
    *)                              echo "$1";;
  esac
}

shortcode(){
  local lc; lc="$(lower "$1")"
  if [[ "$lc" != *vpn* ]] && is_ui_module "$lc"; then echo ui; return 0; fi
  case "$lc" in
    *vpn*) echo vpn;; *umbrella*) echo umbrella;;
    *dart*) echo dart;; *iseposture*) echo ise;; *nvm*) echo nvm;;
    *thousandeyes*) echo te;; *zta*) echo zta;;
    *firewallposture*|*hostscan*) echo sfp;; *posture*) echo posture;;
    *amp*) echo amp;; *) echo mod;;
  esac
}

usage(){
  cat <<'EOF'
Usage: secureclient-repack.sh [options]

Repackage the Cisco Secure Client macOS predeploy pkg, keeping only the
modules you choose, then sign it for MDM deployment. Interactive by
default; the options below make every step scriptable.

Options:
  --dmg <path>         Use this predeploy DMG (skips the search)
  --search-dir <dir>   Directory to search for the DMG and OrgInfo.json
                       (default: ~/Downloads)
  --keep <codes>       Comma-separated module codes to keep, e.g.
                       "umbrella,dart" or "all". The pinned base modules
                       (vpn, ui) are always kept. Implies non-interactive
                       module selection.
  --identity <id>      Signing identity: a SHA-1 hash or a substring of
                       the "Developer ID Installer" certificate name
  --no-sign            Stop after flattening; keep the unsigned pkg
  --orginfo <path>     Umbrella OrgInfo.json to embed in the deploy script
  --output <dir>       Where to write the results
                       (default: the directory containing the DMG)
  --yes                Skip the choices-outline confirmation prompt
  --help               Show this help and exit
  --version            Show the version and exit

Module codes: vpn ui umbrella dart ise nvm te zta sfp posture amp
(only codes present in your package apply; the interactive menu shows
what the package actually contains).

Examples:
  secureclient-repack.sh
  secureclient-repack.sh --keep umbrella --yes
  secureclient-repack.sh --dmg ~/pkgs/csc.dmg --keep all --no-sign --output /tmp/out
EOF
}

# ---------- argument parsing --------------------------------------------------
DMG_ARG=""; SEARCH_DIR="$HOME/Downloads"; KEEP_ARG=""; IDENTITY_ARG=""
NO_SIGN=0; ORG_ARG=""; OUT_DIR=""; ASSUME_YES=0

need_val(){ [[ $# -ge 2 ]] || die "$1 requires a value (see --help)"; }

parse_args(){
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dmg)        need_val "$@"; DMG_ARG="$2"; shift 2;;
      --search-dir) need_val "$@"; SEARCH_DIR="$2"; shift 2;;
      --keep)       need_val "$@"; KEEP_ARG="$2"; shift 2;;
      --identity)   need_val "$@"; IDENTITY_ARG="$2"; shift 2;;
      --no-sign)    NO_SIGN=1; shift;;
      --orginfo)    need_val "$@"; ORG_ARG="$2"; shift 2;;
      --output)     need_val "$@"; OUT_DIR="$2"; shift 2;;
      --yes)        ASSUME_YES=1; shift;;
      --help|-h)    usage; exit 0;;
      --version)    echo "secureclient-repack $VERSION"; exit 0;;
      *)            die "Unknown option: $1 (see --help)";;
    esac
  done
}

# ---------- XSLT emitters -----------------------------------------------------
# map.xsl: emit  choiceId <tab> pkgRefId <tab> #payloadFolder  for every choice
write_map_xsl(){
  cat > "$1" <<'XSL'
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:for-each select="//choice[@id]">
      <xsl:variable name="cid" select="@id"/>
      <xsl:for-each select=".//pkg-ref/@id">
        <xsl:variable name="rid" select="."/>
        <xsl:value-of select="$cid"/><xsl:text>&#9;</xsl:text>
        <xsl:value-of select="$rid"/><xsl:text>&#9;</xsl:text>
        <xsl:for-each select="//pkg-ref[@id=$rid]">
          <xsl:if test="normalize-space(.)!=''"><xsl:value-of select="normalize-space(.)"/></xsl:if>
        </xsl:for-each>
        <xsl:text>&#10;</xsl:text>
      </xsl:for-each>
    </xsl:for-each>
  </xsl:template>
</xsl:stylesheet>
XSL
}

# strip.xsl: identity transform dropping matched line/choice/pkg-ref.
# The drop sets are tested inside the template bodies rather than in match
# patterns because XSLT 1.0 forbids variable references in match patterns
# (current libxslt enforces this).
write_strip_xsl(){
  cat > "$1" <<'XSL'
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="xml" encoding="utf-8" cdata-section-elements="script"/>
  <xsl:param name="dropChoices"/>
  <xsl:param name="dropRefs"/>
  <xsl:template match="@*|node()">
    <xsl:copy><xsl:apply-templates select="@*|node()"/></xsl:copy>
  </xsl:template>
  <xsl:template match="line[@choice]">
    <xsl:if test="not(contains($dropChoices, concat(' ', @choice, ' ')))">
      <xsl:copy><xsl:apply-templates select="@*|node()"/></xsl:copy>
    </xsl:if>
  </xsl:template>
  <xsl:template match="choice[@id]">
    <xsl:if test="not(contains($dropChoices, concat(' ', @id, ' ')))">
      <xsl:copy><xsl:apply-templates select="@*|node()"/></xsl:copy>
    </xsl:if>
  </xsl:template>
  <xsl:template match="pkg-ref[@id]">
    <xsl:if test="not(contains($dropRefs, concat(' ', @id, ' ')))">
      <xsl:copy><xsl:apply-templates select="@*|node()"/></xsl:copy>
    </xsl:if>
  </xsl:template>
</xsl:stylesheet>
XSL
}

# ---------- pure logic (testable) ---------------------------------------------
# discover module leaf-choice ids from the choices-outline; fills IDS
read_choice_ids(){
  IDS=()
  while IFS= read -r line; do IDS+=("$line"); done < <(awk '
    /<choices-outline>/{f=1}
    /<\/choices-outline>/{f=0}
    f && /<line[[:space:]]+choice="[^"]*"[[:space:]]*\/>/ {
      s=$0; match(s,/choice="[^"]*"/); print substr(s,RSTART+8,RLENGTH-9)
    }' "$1")
}

# init keep-state from IDS: pinned (vpn/ui) forced on, rest off; fills KEEP
init_keep_state(){
  KEEP=()
  for i in "${!IDS[@]}"; do
    if is_pinned "${IDS[$i]}"; then KEEP[i]=1; else KEEP[i]=0; fi
  done
}

# apply a --keep spec ("all" or csv of module codes) to IDS/KEEP
apply_keep_spec(){
  local spec tok matched avail
  spec="$(lower "$1")"
  init_keep_state
  if [[ "$spec" == "all" ]]; then
    for i in "${!IDS[@]}"; do KEEP[i]=1; done
    return 0
  fi
  # shellcheck disable=SC2086  # intentional word splitting of the csv spec
  for tok in $(printf '%s' "$spec" | tr ',' ' '); do
    matched=0
    for i in "${!IDS[@]}"; do
      if [[ "$(shortcode "${IDS[$i]}")" == "$tok" ]]; then KEEP[i]=1; matched=1; fi
    done
    if [[ $matched -eq 0 ]]; then
      avail=""
      for i in "${!IDS[@]}"; do avail+=" $(shortcode "${IDS[$i]}")"; done
      die "--keep: no module in this package matches '$tok' (available:$avail)"
    fi
  done
}

# build padded keep/drop choice sets + filename tag + umbrella flag from IDS/KEEP
build_keep_sets(){
  KEEP_CH=" "; DROP_CH=" "; TAG=""; UMB=0
  for i in "${!IDS[@]}"; do
    if [[ ${KEEP[$i]} -eq 1 ]]; then
      KEEP_CH+="${IDS[$i]} "; TAG+="-$(shortcode "${IDS[$i]}")"
      [[ "$(lower "${IDS[$i]}")" == *umbrella* ]] && UMB=1
    else
      DROP_CH+="${IDS[$i]} "
    fi
  done
  return 0
}

# from a map.txt, derive the ref sets:
#   KEEP_REF    = pkg-refs used by kept choices (never drop a shared payload)
#   DROP_REF    = refs only dropped choices use
#   DROP_FOLDER = payload folders that become orphaned
compute_ref_sets(){
  local map="$1" cid rid folder f
  KEEP_REF=" "
  while IFS=$'\t' read -r cid rid folder; do
    [[ -z "$rid" ]] && continue
    if [[ "$KEEP_CH" == *" $cid "* ]]; then
      [[ "$KEEP_REF" == *" $rid "* ]] || KEEP_REF+="$rid "
    fi
  done < "$map"

  # DROP_FOLDER is newline-delimited: payload names may contain spaces, and a
  # space-separated set would split them into tokens that silently match nothing.
  DROP_REF=" "; DROP_FOLDER=$'\n'
  while IFS=$'\t' read -r cid rid folder; do
    [[ -z "$rid" ]] && continue
    if [[ "$DROP_CH" == *" $cid "* && "$KEEP_REF" != *" $rid "* ]]; then
      [[ "$DROP_REF" == *" $rid "* ]] || DROP_REF+="$rid "
      f="${folder#\#}"
      if [[ -n "$f" ]]; then
        validate_payload_name "$f"
        [[ "$DROP_FOLDER" == *$'\n'"$f"$'\n'* ]] || DROP_FOLDER+="$f"$'\n'
      fi
    fi
  done < "$map"
  return 0
}

# verify the transform against IDS/KEEP: every kept choice must have survived
# and every dropped choice must be gone.
# -F throughout: a choice id is a literal, and a regex metacharacter in one
# (a dot, say) would otherwise match a different choice and mis-fire the guard.
verify_choices(){
  local dist="$1" i cid
  for i in "${!IDS[@]}"; do
    cid="${IDS[$i]}"
    if [[ ${KEEP[$i]} -eq 1 ]]; then
      grep -qF "choice=\"$cid\"" "$dist" || die "Kept choice $cid vanished after transform — original saved at ${WORK:-the work directory}/Distribution.orig"
    else
      grep -qF "choice=\"$cid\"" "$dist" && die "Dropped choice $cid still present after transform — aborting."
    fi
  done
  return 0
}

# validate an OrgInfo.json candidate (really JSON + expected keys).
# plutil -convert is used because plutil -lint does not accept JSON input, but
# it accepts *any* property-list format — an XML plist named OrgInfo.json would
# pass — so the object check below is what pins it to JSON.
check_orginfo(){
  local first k
  first="$(tr -d '[:space:]' < "$1" | head -c 1)"
  [[ "$first" == "{" ]] || die "OrgInfo.json is not a JSON object: $1"
  plutil -convert xml1 "$1" -o /dev/null >/dev/null 2>&1 || die "OrgInfo.json is not valid JSON: $1"
  for k in organizationId fingerprint userId; do
    # match the key, not the same text appearing in some value
    grep -q "\"$k\"[[:space:]]*:" "$1" || echo "  warning: '$k' not found in OrgInfo.json — double-check it is the dashboard file."
  done
}

# emit the root shell script that deploys OrgInfo.json on the endpoint.
# OrgInfo ships as a script, never as a pkg: a config-only pkg has no app
# bundle, so bundle-ID based MDM detection (e.g. Intune's PKG app type) would
# never report it installed. A root script needs no detection and matches
# Cisco's own deployment guidance.
#
# The profile is embedded base64-encoded rather than inside a heredoc. A heredoc
# ends at any line equal to its delimiter, so a profile containing that line
# would close it early and turn the remainder into commands run as root on every
# endpoint. Base64 has no delimiter to break out of.
write_orginfo_script(){
  local org="$1" out="$2" b64
  b64="$(base64 < "$org" | tr -d '\n')"
  # shellcheck disable=SC2016  # the single-quoted lines are the generated script's own text
  printf '%s\n' \
    '#!/bin/bash' \
    '# Deploy as a root shell script via your MDM (Intune, Jamf Pro, Kandji, ...).' \
    '# Drops the Umbrella OrgInfo.json where Secure Client consumes it on first launch.' \
    'set -e' \
    'DIR="/opt/cisco/secureclient/umbrella"' \
    'mkdir -p "$DIR"' \
    '# The profile is embedded base64-encoded so that no part of its content can' \
    '# be interpreted as shell.' \
    "ORGINFO_B64='$b64'" \
    '# -D decodes on macOS (BSD base64); -d is the GNU spelling.' \
    'if printf %s "$ORGINFO_B64" | base64 -D > "$DIR/OrgInfo.json" 2>/dev/null; then' \
    '  :' \
    'else' \
    '  printf %s "$ORGINFO_B64" | base64 -d > "$DIR/OrgInfo.json"' \
    'fi' \
    'chmod 644 "$DIR/OrgInfo.json"' \
    'chown root:wheel "$DIR/OrgInfo.json" 2>/dev/null || true' \
    '# Note: on a client already registered, the drop file is ignored until' \
    '# "$DIR/data" is cleared (or the Umbrella module is reinstalled).' \
    'echo "OrgInfo.json deployed to $DIR"' > "$out"
  chmod +x "$out"
}

# ---------- test guard --------------------------------------------------------
# When sourced with SECURECLIENT_REPACK_TEST set, expose the functions above
# without running the pipeline (used by the bats suite).
if [[ -n "${SECURECLIENT_REPACK_TEST:-}" ]]; then
  # shellcheck disable=SC2317  # the exit is the fallback when executed rather than sourced
  return 0 2>/dev/null || exit 0
fi

parse_args "$@"

# ---------- preflight ---------------------------------------------------------
[[ "$(uname)" == "Darwin" ]] || die "Run this on macOS."
for t in hdiutil pkgutil productsign security awk find xsltproc plutil; do
  command -v "$t" >/dev/null || die "$t not found."
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/secureclient-repack.XXXXXX")"

MOUNT=""
cleanup(){
  local status=$?
  [[ -n "$MOUNT" ]] && hdiutil detach "$MOUNT" >/dev/null 2>&1 || true
  if [[ -n "${WORK:-}" && -d "$WORK" ]]; then
    if [[ $status -eq 0 ]]; then
      rm -rf "$WORK"
    else
      echo "Work directory kept for inspection: $WORK" >&2
    fi
  fi
}
trap cleanup EXIT

# ---------- 1. locate the DMG -------------------------------------------------
if [[ -n "$DMG_ARG" ]]; then
  DMG="${DMG_ARG/#\~/$HOME}"
  [[ -f "$DMG" ]] || die "DMG not found: $DMG"
else
  echo "== Locating Secure Client DMG in $SEARCH_DIR =="
  [[ -d "$SEARCH_DIR" ]] || die "Search directory not found: $SEARCH_DIR"
  DMGS=()
  while IFS= read -r f; do DMGS+=("$f"); done \
    < <(find "$SEARCH_DIR" -maxdepth 1 -type f -iname '*secure*client*.dmg' 2>/dev/null | sort)
  (( ${#DMGS[@]} > 0 )) || die "No Secure Client DMG found in $SEARCH_DIR (or pass --dmg <path>)."

  if (( ${#DMGS[@]} == 1 )); then
    DMG="${DMGS[0]}"
  elif [[ -n "$KEEP_ARG" || $ASSUME_YES -eq 1 ]]; then
    die "Multiple DMGs found in $SEARCH_DIR — pass --dmg <path> when running non-interactively."
  else
    echo "Multiple DMGs found:"
    PS3="Select a DMG (number): "
    select choice in "${DMGS[@]}"; do
      [[ -n "${choice:-}" ]] && { DMG="$choice"; break; }
      echo "Pick a valid number."
    done
  fi
fi
echo "Using: $DMG"
VER="$(printf '%s' "$DMG" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
[[ -n "$VER" ]] || VER="custom"

[[ -n "$OUT_DIR" ]] || OUT_DIR="$(cd "$(dirname "$DMG")" && pwd)"
OUT_DIR="${OUT_DIR/#\~/$HOME}"
mkdir -p "$OUT_DIR"

# ---------- 2. mount + copy pkg out ------------------------------------------
echo "== Mounting DMG =="
MOUNT="$(hdiutil attach -nobrowse "$DMG" | awk -F'\t' '/\/Volumes\//{print $NF}' | tail -1)"
[[ -n "$MOUNT" ]] || die "Could not mount DMG."
SRC="$(find "$MOUNT" -maxdepth 1 -type f -name '*.pkg' 2>/dev/null | sort | head -1)"
[[ -n "$SRC" ]] || die "No .pkg found on the mounted DMG."
cp "$SRC" "$WORK/original.pkg"
hdiutil detach "$MOUNT" >/dev/null; MOUNT=""
echo "Copied: $(basename "$SRC")"

# ---------- 3. expand ---------------------------------------------------------
echo "== Expanding =="
pkgutil --expand "$WORK/original.pkg" "$WORK/expanded"
DIST="$WORK/expanded/Distribution"
[[ -f "$DIST" ]] || die "No Distribution file in expanded package."
cp "$DIST" "$WORK/Distribution.orig"

read_choice_ids "$WORK/Distribution.orig"
(( ${#IDS[@]} > 0 )) || die "Could not read module list from Distribution — inspect $DIST by hand."

init_keep_state

# ---------- module selection --------------------------------------------------
if [[ -n "$KEEP_ARG" ]]; then
  apply_keep_spec "$KEEP_ARG"
else
  while true; do
    echo
    echo "Modules in this package — choose which to KEEP (pinned = required base):"
    echo
    for i in "${!IDS[@]}"; do
      m=" "; [[ ${KEEP[$i]} -eq 1 ]] && m="x"
      printf "  %2d) [%s] %s\n" "$((i+1))" "$m" "$(friendly "${IDS[$i]}")"
    done
    echo
    echo "  toggle: numbers (e.g. 2 6)    a: keep all    n: pinned only    Enter: accept"
    read -r -p "> " reply || reply=""
    [[ -z "$reply" ]] && break
    case "$reply" in
      a|A) for i in "${!IDS[@]}"; do KEEP[i]=1; done ;;
      n|N) for i in "${!IDS[@]}"; do is_pinned "${IDS[$i]}" && KEEP[i]=1 || KEEP[i]=0; done ;;
      *)
        # shellcheck disable=SC2086  # intentional word splitting of the reply
        for tok in $reply; do
          [[ "$tok" =~ ^[0-9]+$ ]] || { echo "  ignoring '$tok'"; continue; }
          idx=$((tok-1))
          if (( idx < 0 || idx >= ${#IDS[@]} )); then echo "  out of range: $tok"; continue; fi
          if is_pinned "${IDS[$idx]}"; then
            echo "  ${IDS[$idx]} is a pinned base component and stays selected."
          else
            KEEP[idx]=$(( 1 - KEEP[idx] ))
          fi
        done ;;
    esac
  done
fi

build_keep_sets
echo; echo "Keeping:$TAG"

# ---------- source OrgInfo.json early if Umbrella is kept --------------------
ORG=""
if [[ $UMB -eq 1 ]]; then
  echo; echo "== Umbrella kept — locating OrgInfo.json =="
  if [[ -n "$ORG_ARG" ]]; then
    ORG="${ORG_ARG/#\~/$HOME}"
    [[ -f "$ORG" ]] || die "OrgInfo file not found: $ORG"
    echo "Using: $ORG"
  else
    CANDS=()
    while IFS= read -r f; do CANDS+=("$f"); done \
      < <(find "$SEARCH_DIR" -maxdepth 1 -type f -iname 'orginfo*.json' 2>/dev/null | sort)
    if (( ${#CANDS[@]} == 1 )); then
      ORG="${CANDS[0]}"; echo "Found: $ORG"
    elif (( ${#CANDS[@]} > 1 )); then
      if [[ -n "$KEEP_ARG" || $ASSUME_YES -eq 1 ]]; then
        die "Multiple OrgInfo files in $SEARCH_DIR — pass --orginfo <path> when running non-interactively."
      fi
      echo "Multiple OrgInfo files found:"
      PS3="Select OrgInfo.json (number): "
      select choice in "${CANDS[@]}"; do [[ -n "${choice:-}" ]] && { ORG="$choice"; break; }; done
    elif [[ -n "$KEEP_ARG" || $ASSUME_YES -eq 1 ]]; then
      echo "No OrgInfo.json found in $SEARCH_DIR — skipping. Umbrella will not register until it is deployed separately."
    else
      echo "No OrgInfo.json found in $SEARCH_DIR."
      while :; do
        read -r -p "Path to OrgInfo.json (drag file in, or Enter to skip): " ORG || ORG=""
        [[ -z "$ORG" ]] && { echo "Skipping OrgInfo — Umbrella will not register until it is deployed separately."; break; }
        ORG="${ORG/#\~/$HOME}"; ORG="$(printf '%s' "$ORG" | sed -e "s/^'//" -e "s/'$//")"
        [[ -f "$ORG" ]] && break
        echo "  not found: $ORG"
      done
    fi
  fi
  [[ -n "$ORG" ]] && check_orginfo "$ORG"
fi

# ---------- 4. FULL strip via XSLT -------------------------------------------
write_map_xsl "$WORK/map.xsl"
write_strip_xsl "$WORK/strip.xsl"

xsltproc "$WORK/map.xsl" "$WORK/Distribution.orig" > "$WORK/map.txt"
compute_ref_sets "$WORK/map.txt"

# transform Distribution
xsltproc --stringparam dropChoices "$DROP_CH" --stringparam dropRefs "$DROP_REF" \
  "$WORK/strip.xsl" "$WORK/Distribution.orig" > "$DIST"

# delete orphaned payload folders. Names were validated when the drop set was
# built, and the list is newline-delimited so names containing spaces survive.
while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  if [[ -d "$WORK/expanded/$f" ]]; then
    rm -rf "$WORK/expanded/$f"
    echo "  removed payload: $f"
  fi
done <<< "$DROP_FOLDER"

# ---------- guards ------------------------------------------------------------
verify_choices "$DIST"
# every payload still referenced must still exist on disk
while IFS= read -r ref; do
  f="${ref#\#}"; [[ -n "$f" ]] || continue
  [[ -d "$WORK/expanded/$f" ]] || die "Distribution still references missing payload '$f' — aborting to avoid a broken installer."
done < <(grep 'pkg-ref' "$DIST" | grep -oE '#[^"<[:space:]]+' | sort -u)

echo; echo "== choices-outline AFTER =="
awk '/<choices-outline>/,/<\/choices-outline>/' "$DIST"
echo
if [[ $ASSUME_YES -eq 0 ]]; then
  read -r -p "Outline correct? Enter to build & sign, Ctrl-C to abort. " _ || true
fi

# ---------- 5. re-flatten -----------------------------------------------------
rm -f "$WORK/Distribution.orig" "$WORK/map.xsl" "$WORK/strip.xsl" "$WORK/map.txt"
UNSIGNED="$WORK/Cisco Secure Client-${VER}${TAG}.pkg"
pkgutil --flatten "$WORK/expanded" "$UNSIGNED"
echo "Built unsigned: $(basename "$UNSIGNED")"

# ---------- 6. OrgInfo deploy script ------------------------------------------
# Written before signing so it is still produced when no signing identity is
# present — that is the "sign it on a machine that holds the cert" workflow,
# and the OrgInfo script is needed either way.
ORG_SCRIPT=""
if [[ $UMB -eq 1 && -n "$ORG" ]]; then
  ORG_SCRIPT="$OUT_DIR/deploy-orginfo.sh"
  write_orginfo_script "$ORG" "$ORG_SCRIPT"
fi

# ---------- 7. sign, or keep the unsigned pkg --------------------------------
SIGNED=""; UNSIGNED_OUT=""
if [[ $NO_SIGN -eq 1 ]]; then
  UNSIGNED_OUT="$OUT_DIR/$(basename "$UNSIGNED")"
  cp "$UNSIGNED" "$UNSIGNED_OUT"
  echo; echo "Skipping signing (--no-sign)."
else
  echo; echo "== Developer ID Installer identities =="
  ILINES=()
  while IFS= read -r line; do ILINES+=("$line"); done \
    < <(security find-identity -v -p basic 2>/dev/null | grep "Developer ID Installer" || true)

  if (( ${#ILINES[@]} == 0 )); then
    UNSIGNED_OUT="$OUT_DIR/$(basename "$UNSIGNED")"
    cp "$UNSIGNED" "$UNSIGNED_OUT"
    echo "No 'Developer ID Installer' identity found."
    echo "Sign the unsigned pkg on a machine that holds the cert, then upload."
  else
    IHASH=(); INAME=()
    for l in "${ILINES[@]}"; do
      IHASH+=("$(awk '{print $2}' <<<"$l")")
      INAME+=("$(sed -E 's/^[^"]*"([^"]*)".*/\1/' <<<"$l")")
    done

    SEL=-1
    if [[ -n "$IDENTITY_ARG" ]]; then
      for i in "${!IHASH[@]}"; do
        if [[ "${IHASH[$i]}" == "$IDENTITY_ARG" || "${INAME[$i]}" == *"$IDENTITY_ARG"* ]]; then
          SEL=$i; break
        fi
      done
      (( SEL >= 0 )) || die "No 'Developer ID Installer' identity matches '$IDENTITY_ARG'."
    elif (( ${#IHASH[@]} == 1 )); then
      SEL=0
    elif [[ -n "$KEEP_ARG" || $ASSUME_YES -eq 1 ]]; then
      die "Multiple signing identities found — pass --identity <name-or-hash> when running non-interactively."
    else
      echo "Multiple signing identities:"
      for i in "${!INAME[@]}"; do printf "  %d) %s\n" "$((i+1))" "${INAME[$i]}"; done
      while :; do
        read -r -p "Choose identity number: " pick || pick=""
        if [[ "$pick" =~ ^[0-9]+$ ]] && (( pick>=1 && pick<=${#IHASH[@]} )); then SEL=$((pick-1)); break; fi
        echo "Pick a valid number."
      done
    fi
    echo "Signing with: ${INAME[$SEL]}"

    SIGNED="$OUT_DIR/Cisco Secure Client-${VER}${TAG}-signed.pkg"
    rm -f "$SIGNED"
    productsign --sign "${IHASH[$SEL]}" "$UNSIGNED" "$SIGNED"
    echo; echo "== Signature =="
    pkgutil --check-signature "$SIGNED"
  fi
fi

# ---------- done --------------------------------------------------------------
echo
echo "DONE."
if [[ -n "$SIGNED" ]]; then
  echo "Signed client pkg   : $SIGNED"
else
  echo "Unsigned client pkg : $UNSIGNED_OUT"
fi
[[ -n "$ORG_SCRIPT" ]] && echo "OrgInfo script      : $ORG_SCRIPT"
echo
echo "Next steps:"
echo "  - Upload the pkg to your MDM as a macOS installer package. It now"
echo "    advertises only the kept modules."
[[ -n "$ORG_SCRIPT" ]] && {
  echo "  - Deploy deploy-orginfo.sh as a root shell script via your MDM"
  echo "    (Intune, Jamf Pro, Kandji, ...) before or alongside the client."
}
echo "  - Umbrella and other modules may also need system-extension approval"
echo "    and configuration profiles — see the README for MDM specifics."
