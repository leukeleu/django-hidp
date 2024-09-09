#!/bin/bash
##
# A helper script for complex Makefile tasks.
##

# Unofficial Bash Strict Mode
set -euo pipefail

# Determine if we're in GitHub Actions
IS_GITHUB_ACTIONS=${GITHUB_ACTIONS:-false}

# Utility: Escape newlines for GitHub Actions output
escape_newlines() {
  # Replace newlines with %0A in order to preserve them in GitHub Actions output
  awk '{printf "%s%%0A", $0}'
}

# Utility: Output a GitHub workflow error command
github_error() {
  local file=${1}
  local title=${2}
  local escaped_message
  escaped_message=$(echo "${3}" | escape_newlines)
  echo "::error file=${file},title=${title}::${escaped_message}"
}

# Task: Check if locale files are up-to-date
check_locale_diff() {
  local diff_files
  local repo_root
  # Find files with differences
  diff_files=$(git -P diff --name-only -- hidp/locale)
  if [ -n "${diff_files}" ]; then
    repo_root=$(git rev-parse --show-toplevel)
    for file in ${diff_files}; do
      # Get the full path of the file
      filepath="${repo_root}/${file}"
      # Get the diff output for this specific file
      diff_output=$(git diff -- "${filepath}")
      # Make sure the diff output is not empty
      if [ -z "${diff_output}" ]; then continue; fi
      if [[ "${IS_GITHUB_ACTIONS}" == "true" ]]; then
        # Annotate the file with the diff output
        github_error "$filepath" "Message catalog is out of date" "${diff_output}"
      else
        echo "Message catalog is out of date for ${file}:"
        echo "${diff_output}"
      fi
    done
    return 1
  fi
  return 0
}

# Task: Check for fuzzy translations
check_fuzzy_translations() {
  local grep_files
  # Find files with fuzzy translation markers
  # Ignore the exit code 1 (no matches) from grep so the script doesn't exit prematurely
  grep_files=$(grep -rl '#, fuzzy\n\| msgid' hidp/locale/ || test $? = 1)
  if [ -n "${grep_files}" ]; then
    for file in ${grep_files}; do
      # Get the matching lines for this specific file (including context around the match)
      grep_output=$(grep -C1 '#, fuzzy\n\| msgid' "${file}")
      if [[ "${IS_GITHUB_ACTIONS}" == "true" ]]; then
        # Annotate the file with the grep output
        filepath=$(readlink -f "$file")
        github_error "$filepath" "Fuzzy translation(s) found" "$grep_output"
      else
        echo "Fuzzy translation(s) found in $file:"
        echo "$grep_output"
      fi
    done
    return 1
  fi
  return 0
}

# Dispatch to the appropriate task based on the first argument
case "${1:-help}" in
  check-locale-diff)
    check_locale_diff
    exit $? # Exit with the status check_locale_diff returned
    ;;
  check-fuzzy-translations)
    check_fuzzy_translations
    exit $? # Exit with the status check_fuzzy_translations returned
    ;;
  *)
    echo "Usage: $0 {check-locale-diff|check-fuzzy-translations}"
    exit 1
    ;;
esac
