#!/usr/bin/env bash
# Files or updates the tracking issue for a scheduled run whose main job
# failed or was cancelled before its own triage step finished.
#
# The nightly workflows triage their failures in a step of the failing job,
# which runs on the same runner. When the runner itself goes ("The hosted
# runner lost communication with the server"), that step goes with it, the
# log is lost, and nothing is filed. Each of those workflows therefore ends
# with a small job on a fresh runner that calls this script when the main job
# did not record that its triage step succeeded.
#
#   LABEL, LABEL_COLOR, LABEL_DESC   the workflow's "broken job" label
#   TITLE                            title for a new issue (the date is appended)
#   WORKFLOW, JOB_RESULT, RUN_URL    what to report
#   DRY_RUN=1                        print the issue instead of filing it
#
# Needs GH_TOKEN with issues: write, and GH_REPO or a checkout for `gh`.
set -euo pipefail

for v in LABEL LABEL_COLOR LABEL_DESC TITLE WORKFLOW JOB_RESULT RUN_URL; do
    if [ -z "${!v:-}" ]; then
        echo "error: $v is not set" >&2
        exit 1
    fi
done

today=$(date -u +%F)
body=$(cat <<EOF
The scheduled **$WORKFLOW** run ended (\`$JOB_RESULT\`) before its own triage
step finished, so the run could not report why.

- Run: $RUN_URL

The usual cause is the runner itself failing: the run's annotations then say
"The hosted runner lost communication with the server", and the job log is
lost with it. A single occurrence is most likely GitHub's; rerun the workflow
by hand to check. If it recurs, something in the job is exhausting the runner
(memory, disk, processes) and needs finding before the job means anything.
EOF
)

if [ "${DRY_RUN:-}" = "1" ]; then
    echo "DRY_RUN: would file under '$LABEL' (title '$TITLE ($today)'):"
    echo "$body"
    exit 0
fi

# This is the last report a lost run gets, so a transient API error must not
# drop it: each call is tried three times.
retry() {
    local i
    for i in 1 2 3; do
        "$@" && return 0
        echo "attempt $i of: $* failed" >&2
        [ "$i" -lt 3 ] && sleep $((i * 10))
    done
    return 1
}

# One open issue per label, as the workflows' own triage steps keep it:
# comment on the open one, else open one. A label that cannot be created
# (it usually exists already) only costs the label: the issue is filed
# without it rather than not at all.
labelled=(--label "$LABEL")
names=$(retry gh label list --search "$LABEL" --json name --jq '.[].name') || names=""
if ! grep -qx -- "$LABEL" <<<"$names" &&
   ! retry gh label create "$LABEL" --color "$LABEL_COLOR" --description "$LABEL_DESC"; then
    echo "warning: could not create label $LABEL; filing without it" >&2
    labelled=()
fi
existing=""
if [ ${#labelled[@]} -gt 0 ]; then
    # A list that keeps failing files a possible duplicate rather than nothing.
    existing=$(retry gh issue list --label "$LABEL" --state open --json number --jq '.[0].number // empty') || existing=""
fi
if [ -n "$existing" ]; then
    echo "Commenting on existing issue #$existing ($LABEL)"
    retry gh issue comment "$existing" --body "$body"
else
    echo "Opening a new $LABEL issue"
    retry gh issue create "${labelled[@]}" --title "$TITLE ($today)" --body "$body"
fi
