#!/bin/sh
# Build the photo-sharing page and deploy it to Cloudflare Pages.
#   ./deploy.sh preview      -> photos.find-your-seat.pages.dev  (Turnstile test keys, always pass)
#   ./deploy.sh production   -> find-your-seat.pages.dev / mathewsandswaroopa.com (real Turnstile widget)
set -e
cd "$(dirname "$0")"
case "$1" in
  preview)    FINDER_TURNSTILE_SITEKEY=1x00000000000000000000AA FINDER_PHOTOS=1 python3 ../seating_finder.py; BRANCH=photos ;;
  production) FINDER_PHOTOS=1 python3 ../seating_finder.py; BRANCH=main ;;
  *) echo "usage: $0 preview|production"; exit 1 ;;
esac
npx wrangler pages deploy --project-name find-your-seat --branch "$BRANCH" --commit-dirty=true
