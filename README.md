# loghook

## what is this?

A webhook recipient for GitHub. Just emits events to standard output.

A chunk of this - noted in the source, with thanks! - is directly lifted from
@phayes's `hookserve`:

https://github.com/phayes/hookserve/blob/master/hookserve/hookserve.go

## how?

1. generate a shared secret somehow and stash it in the environment variable `LOGHOOK_GITHUB_WEBHOOK_SECRET`

```
export LOGHOOK_GITHUB_WEBHOOK_SECRET=$(openssl rand -hex 64)
```

2. start `loghook`

```
./loghook
```

## more?

```
./loghook -help
```
