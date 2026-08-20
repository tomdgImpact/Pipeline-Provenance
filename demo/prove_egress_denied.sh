#!/usr/bin/env bash
# Runner-level proof of I4.
#
# The job that calls this declares a default-deny egress policy with an
# allowlist that does not contain the host below. If the request succeeds, the
# policy is not being enforced and the job must fail — reporting a control that
# is not in force is worse than having no control, because it reads as one.
set -uo pipefail

TARGET="${1:-https://example.com}"

echo "Attempting to reach an unlisted host: ${TARGET}"
if curl --silent --show-error --max-time 10 --output /dev/null "${TARGET}"; then
  echo "::error title=I4 not enforced::Reached ${TARGET} from a job whose egress" \
       "policy denies it. The control is declared and not in force."
  exit 1
fi

echo "Refused, as declared. I4 is enforced on this runner."
