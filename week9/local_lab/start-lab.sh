#!/usr/bin/env bash
set -euo pipefail
IMAGE='docker.elastic.co/elasticsearch/elasticsearch@sha256:13b4a40bb095774f5fda635e45fd5677cc6a26565e42b24997b0c72b88e75984'
NAME='threat-hunting-week9-es'
if podman container exists "$NAME"; then
  podman inspect "$NAME" | python3 -c '
import json,sys
c=json.load(sys.stdin)[0]
checks=[
 (c["HostConfig"]["Memory"]==3221225472,"Unexpected memory limit"),
 (c["HostConfig"]["PortBindings"]=={"9200/tcp":[{"HostIp":"127.0.0.1","HostPort":"9201"}]},"Unexpected port binding"),
 (c["ImageDigest"]=="sha256:13b4a40bb095774f5fda635e45fd5677cc6a26565e42b24997b0c72b88e75984","Unexpected image"),
 ("xpack.security.enabled=false" in c["Config"]["Env"],"Unexpected authentication setting")]
for ok,message in checks:
 if not ok:
  print(message,file=sys.stderr)
  sys.exit(1)
'
  podman start "$NAME"
else
  podman run --pull=never -d --name "$NAME" \
    --memory=3g --cpus=2 --pids-limit=512 \
    --cap-drop=ALL --security-opt=no-new-privileges \
    -p 127.0.0.1:9201:9200 \
    -e cluster.name=threat-hunting-week9 \
    -e node.name=week9-local \
    -e discovery.type=single-node \
    -e xpack.security.enabled=false \
    -e xpack.ml.enabled=false \
    -e ingest.geoip.downloader.enabled=false \
    -e 'ES_JAVA_OPTS=-Xms1g -Xmx1g' \
    -v threat-hunting-week9-es-data:/usr/share/elasticsearch/data \
    "$IMAGE"
fi
for i in $(seq 1 90); do
  if curl --silent --fail --max-time 3 http://127.0.0.1:9201/ >/dev/null; then
    printf '\nElasticsearch is ready at http://127.0.0.1:9201\n'
    exit 0
  fi
  sleep 2
done
printf '\nElasticsearch did not become ready within 3 minutes.\n' >&2
podman logs --tail 60 "$NAME" >&2
exit 1
