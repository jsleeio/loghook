#!/bin/sh

# this script is intended to make testing easier, particularly with the
# SHA1-HMAC validation.

target="http://localhost:3000/post"
hmackey="$LOGHOOK_GITHUB_WEBHOOK_SECRET"
event="alert"
n=""

while getopts "e:f:k:nt:" opt ; do
  case "$opt" in
    e) event="$OPTARG" ;;
    f) file="$OPTARG" ;;
    k) hmackey="$OPTARG" ;;
    t) target="$OPTARG" ;;
    n) n="echo" ;;
    *) echo "invalid options" >&2; exit 1 ;;
  esac
done

$n curl \
  --header 'Content-Type: application/json' \
  --header "X-GitHub-Event: $event" \
  --header "X-Hub-Signature: sha1=$(cat "$file" | tr -d '\n' | openssl sha1 -hmac "$hmackey" | awk '{ print $NF }')" \
  --data @"$file" \
  "$target"
