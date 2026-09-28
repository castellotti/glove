# media

Bakes an offline media toolchain into the harness image: ffmpeg, ImageMagick,
libwebp tools, exiftool and PIL. The tools run as ordinary shell commands under
the ring-1 tool policy (confined to `/work`, rw mounts and `/tmp`, no network).
No settings, no sidecars, no network.

```yaml
extensions:
  media: {}
```
