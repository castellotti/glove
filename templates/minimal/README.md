# minimal

The smallest useful session: one harness, one model, no network except the
model's forwarder, and `work/` as `/work`.

```sh
glove new minimal ~/work/scratch
cd ~/work/scratch
$EDITOR glove-session.yml   # set the llm provider, location and endpoint
glove check && glove up
```
