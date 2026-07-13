#!/usr/bin/env bats
# Tests for secureclient-repack.sh. The script is sourced with
# SECURECLIENT_REPACK_TEST set, which exposes its functions without running
# the pipeline. The fixture Distribution.xml is synthetic — it mirrors the
# structure of an expanded multi-module pkg without any vendor content.

setup() {
  SCRIPT="$BATS_TEST_DIRNAME/../secureclient-repack.sh"
  FIXTURE="$BATS_TEST_DIRNAME/fixtures/Distribution.xml"
  export SECURECLIENT_REPACK_TEST=1
  # shellcheck disable=SC1090
  source "$SCRIPT"
}

# ---------- CLI surface --------------------------------------------------------

@test "--help prints usage and exits cleanly" {
  run env SECURECLIENT_REPACK_TEST= bash "$SCRIPT" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"Usage: secureclient-repack.sh"* ]]
  [[ "$output" == *"--keep"* ]]
  [[ "$output" == *"--no-sign"* ]]
}

@test "--version prints the version" {
  run env SECURECLIENT_REPACK_TEST= bash "$SCRIPT" --version
  [ "$status" -eq 0 ]
  [ "$output" = "secureclient-repack 1.0.0" ]
}

@test "unknown option fails with an error" {
  run env SECURECLIENT_REPACK_TEST= bash "$SCRIPT" --bogus
  [ "$status" -ne 0 ]
  [[ "$output" == *"Unknown option: --bogus"* ]]
}

@test "an option missing its value fails with an error" {
  run env SECURECLIENT_REPACK_TEST= bash "$SCRIPT" --keep
  [ "$status" -ne 0 ]
  [[ "$output" == *"--keep requires a value"* ]]
}

# ---------- vocabulary helpers -------------------------------------------------

@test "is_pinned pins vpn and ui but not optional modules" {
  is_pinned "module_vpn"
  is_pinned "module_ui"
  ! is_pinned "module_umbrella"
  ! is_pinned "module_dart"
}

@test "friendly names known modules" {
  [ "$(friendly module_umbrella)" = "Umbrella Roaming Security" ]
  [ "$(friendly module_dart)" = "DART — Diagnostics & Reporting" ]
  [[ "$(friendly module_vpn)" == *"pinned"* ]]
  [ "$(friendly something_else)" = "something_else" ]
}

@test "shortcode maps choice ids to module codes" {
  [ "$(shortcode module_vpn)" = "vpn" ]
  [ "$(shortcode module_ui)" = "ui" ]
  [ "$(shortcode module_umbrella)" = "umbrella" ]
  [ "$(shortcode module_dart)" = "dart" ]
  [ "$(shortcode module_nvm)" = "nvm" ]
  [ "$(shortcode something_else)" = "mod" ]
}

# ---------- outline discovery and keep selection -------------------------------

@test "read_choice_ids discovers the outline choices in order" {
  read_choice_ids "$FIXTURE"
  [ "${#IDS[@]}" -eq 5 ]
  [ "${IDS[0]}" = "module_vpn" ]
  [ "${IDS[1]}" = "module_ui" ]
  [ "${IDS[2]}" = "module_umbrella" ]
  [ "${IDS[3]}" = "module_dart" ]
  [ "${IDS[4]}" = "module_nvm" ]
}

@test "init_keep_state keeps only the pinned modules" {
  read_choice_ids "$FIXTURE"
  init_keep_state
  [ "${KEEP[0]}" -eq 1 ]
  [ "${KEEP[1]}" -eq 1 ]
  [ "${KEEP[2]}" -eq 0 ]
  [ "${KEEP[3]}" -eq 0 ]
  [ "${KEEP[4]}" -eq 0 ]
}

@test "apply_keep_spec keeps pinned modules plus the requested codes" {
  read_choice_ids "$FIXTURE"
  apply_keep_spec "umbrella"
  [ "${KEEP[0]}" -eq 1 ]
  [ "${KEEP[1]}" -eq 1 ]
  [ "${KEEP[2]}" -eq 1 ]
  [ "${KEEP[3]}" -eq 0 ]
  [ "${KEEP[4]}" -eq 0 ]
}

@test "apply_keep_spec accepts a csv of codes" {
  read_choice_ids "$FIXTURE"
  apply_keep_spec "dart,nvm"
  [ "${KEEP[2]}" -eq 0 ]
  [ "${KEEP[3]}" -eq 1 ]
  [ "${KEEP[4]}" -eq 1 ]
}

@test "apply_keep_spec all keeps everything" {
  read_choice_ids "$FIXTURE"
  apply_keep_spec "all"
  for i in "${!IDS[@]}"; do [ "${KEEP[$i]}" -eq 1 ]; done
}

@test "apply_keep_spec rejects a code not present in the package" {
  read_choice_ids "$FIXTURE"
  run apply_keep_spec "bogus"
  [ "$status" -ne 0 ]
  [[ "$output" == *"no module in this package matches 'bogus'"* ]]
  [[ "$output" == *"available:"* ]]
}

@test "build_keep_sets builds keep/drop sets, tag and umbrella flag" {
  read_choice_ids "$FIXTURE"
  apply_keep_spec "umbrella"
  build_keep_sets
  [[ "$KEEP_CH" == *" module_vpn "* ]]
  [[ "$KEEP_CH" == *" module_umbrella "* ]]
  [[ "$DROP_CH" == *" module_dart "* ]]
  [[ "$DROP_CH" == *" module_nvm "* ]]
  [[ "$DROP_CH" != *" module_vpn "* ]]
  [ "$TAG" = "-vpn-ui-umbrella" ]
  [ "$UMB" -eq 1 ]
}

@test "build_keep_sets leaves the umbrella flag off when umbrella is dropped" {
  read_choice_ids "$FIXTURE"
  apply_keep_spec "dart"
  build_keep_sets
  [ "$UMB" -eq 0 ]
  [ "$TAG" = "-vpn-ui-dart" ]
}

# ---------- XSLT map and ref computation ---------------------------------------

@test "map.xsl emits choice, pkg-ref and payload rows" {
  write_map_xsl "$BATS_TEST_TMPDIR/map.xsl"
  xsltproc "$BATS_TEST_TMPDIR/map.xsl" "$FIXTURE" > "$BATS_TEST_TMPDIR/map.txt"
  grep -q "$(printf 'module_vpn\tcom.example.vpn\t#vpn_module.pkg')" "$BATS_TEST_TMPDIR/map.txt"
  grep -q "$(printf 'module_dart\tcom.example.dart\t#dart_module.pkg')" "$BATS_TEST_TMPDIR/map.txt"
  grep -q "$(printf 'module_dart\tcom.example.common\t#common_module.pkg')" "$BATS_TEST_TMPDIR/map.txt"
  grep -q "$(printf 'module_nvm\tcom.example.common\t#common_module.pkg')" "$BATS_TEST_TMPDIR/map.txt"
}

@test "compute_ref_sets protects a shared pkg-ref while a kept choice still uses it" {
  read_choice_ids "$FIXTURE"
  apply_keep_spec "nvm"
  build_keep_sets
  write_map_xsl "$BATS_TEST_TMPDIR/map.xsl"
  xsltproc "$BATS_TEST_TMPDIR/map.xsl" "$FIXTURE" > "$BATS_TEST_TMPDIR/map.txt"
  compute_ref_sets "$BATS_TEST_TMPDIR/map.txt"
  # dart is dropped but the ref it shares with kept nvm must survive
  [[ "$KEEP_REF" == *" com.example.common "* ]]
  [[ "$DROP_REF" != *" com.example.common "* ]]
  [[ "$DROP_FOLDER" != *" common_module.pkg "* ]]
  # dart's own ref and payload do go
  [[ "$DROP_REF" == *" com.example.dart "* ]]
  [[ "$DROP_FOLDER" == *" dart_module.pkg "* ]]
}

@test "compute_ref_sets drops a shared pkg-ref once every user is dropped" {
  read_choice_ids "$FIXTURE"
  apply_keep_spec "umbrella"
  build_keep_sets
  write_map_xsl "$BATS_TEST_TMPDIR/map.xsl"
  xsltproc "$BATS_TEST_TMPDIR/map.xsl" "$FIXTURE" > "$BATS_TEST_TMPDIR/map.txt"
  compute_ref_sets "$BATS_TEST_TMPDIR/map.txt"
  [[ "$DROP_REF" == *" com.example.common "* ]]
  [[ "$DROP_FOLDER" == *" common_module.pkg "* ]]
  [[ "$KEEP_REF" == *" com.example.umbrella "* ]]
}

# ---------- strip transform and guards ------------------------------------------

@test "strip.xsl removes dropped choices, outline lines and pkg-refs and keeps the rest" {
  read_choice_ids "$FIXTURE"
  apply_keep_spec "umbrella"
  build_keep_sets
  write_map_xsl "$BATS_TEST_TMPDIR/map.xsl"
  write_strip_xsl "$BATS_TEST_TMPDIR/strip.xsl"
  xsltproc "$BATS_TEST_TMPDIR/map.xsl" "$FIXTURE" > "$BATS_TEST_TMPDIR/map.txt"
  compute_ref_sets "$BATS_TEST_TMPDIR/map.txt"
  xsltproc --stringparam dropChoices "$DROP_CH" --stringparam dropRefs "$DROP_REF" \
    "$BATS_TEST_TMPDIR/strip.xsl" "$FIXTURE" > "$BATS_TEST_TMPDIR/Distribution"
  DIST="$BATS_TEST_TMPDIR/Distribution"
  # dropped
  ! grep -q 'choice="module_dart"' "$DIST"
  ! grep -q 'choice="module_nvm"' "$DIST"
  ! grep -q 'id="module_dart"' "$DIST"
  ! grep -q 'com.example.dart' "$DIST"
  ! grep -q 'com.example.nvm' "$DIST"
  ! grep -q 'com.example.common' "$DIST"
  # kept
  grep -q 'choice="module_vpn"' "$DIST"
  grep -q 'choice="module_ui"' "$DIST"
  grep -q 'choice="module_umbrella"' "$DIST"
  grep -q 'com.example.umbrella' "$DIST"
  # outline now lists exactly the three kept choices
  [ "$(awk '/<choices-outline>/,/<\/choices-outline>/' "$DIST" | grep -c '<line ')" -eq 3 ]
}

@test "the kept/dropped guard logic holds on the transformed fixture" {
  read_choice_ids "$FIXTURE"
  apply_keep_spec "dart"
  build_keep_sets
  write_map_xsl "$BATS_TEST_TMPDIR/map.xsl"
  write_strip_xsl "$BATS_TEST_TMPDIR/strip.xsl"
  xsltproc "$BATS_TEST_TMPDIR/map.xsl" "$FIXTURE" > "$BATS_TEST_TMPDIR/map.txt"
  compute_ref_sets "$BATS_TEST_TMPDIR/map.txt"
  xsltproc --stringparam dropChoices "$DROP_CH" --stringparam dropRefs "$DROP_REF" \
    "$BATS_TEST_TMPDIR/strip.xsl" "$FIXTURE" > "$BATS_TEST_TMPDIR/Distribution"
  DIST="$BATS_TEST_TMPDIR/Distribution"
  for i in "${!IDS[@]}"; do
    cid="${IDS[$i]}"
    if [ "${KEEP[$i]}" -eq 1 ]; then
      grep -q "choice=\"$cid\"" "$DIST"
    else
      ! grep -q "choice=\"$cid\"" "$DIST"
    fi
  done
  # the shared ref survives because dart still needs it
  grep -q 'com.example.common' "$DIST"
}

# ---------- OrgInfo handling ----------------------------------------------------

@test "check_orginfo accepts a valid OrgInfo.json" {
  printf '{"organizationId":"1234567","fingerprint":"abc","userId":"7654321"}\n' \
    > "$BATS_TEST_TMPDIR/OrgInfo.json"
  run check_orginfo "$BATS_TEST_TMPDIR/OrgInfo.json"
  [ "$status" -eq 0 ]
  [[ "$output" != *"warning"* ]]
}

@test "check_orginfo rejects invalid JSON" {
  printf 'not json at all\n' > "$BATS_TEST_TMPDIR/OrgInfo.json"
  run check_orginfo "$BATS_TEST_TMPDIR/OrgInfo.json"
  [ "$status" -ne 0 ]
  [[ "$output" == *"not valid JSON"* ]]
}

@test "check_orginfo warns when expected keys are missing" {
  printf '{"organizationId":"1234567"}\n' > "$BATS_TEST_TMPDIR/OrgInfo.json"
  run check_orginfo "$BATS_TEST_TMPDIR/OrgInfo.json"
  [ "$status" -eq 0 ]
  [[ "$output" == *"'fingerprint' not found"* ]]
  [[ "$output" == *"'userId' not found"* ]]
}

@test "write_orginfo_script embeds the JSON and targets the umbrella directory" {
  printf '{"organizationId":"1234567","fingerprint":"abc","userId":"7654321"}\n' \
    > "$BATS_TEST_TMPDIR/OrgInfo.json"
  write_orginfo_script "$BATS_TEST_TMPDIR/OrgInfo.json" "$BATS_TEST_TMPDIR/deploy-orginfo.sh"
  OUT="$BATS_TEST_TMPDIR/deploy-orginfo.sh"
  [ -x "$OUT" ]
  grep -q '/opt/cisco/secureclient/umbrella' "$OUT"
  grep -q '"organizationId":"1234567"' "$OUT"
  grep -q 'ORGINFO_EOF' "$OUT"
  # MDM-neutral wording, not tied to a single product
  grep -q 'via your MDM' "$OUT"
  # the emitted script parses
  bash -n "$OUT"
}
