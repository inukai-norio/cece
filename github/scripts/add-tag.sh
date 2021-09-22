#!/bin/bash

echo "{\"ref\":\"refs/tags/release-$(date +"%Y%m%d-%H%m")\",\"sha\":\"$GITHUB_COMMIT\"}" | \
curl -s -X POST "https://api.github.com/repos/${REPO}/git/refs" \
  -H "Accept: application/vnd.github.v3+json" \
  -H "Authorization: token $GITHUB_TOKEN" \
  -d @-
