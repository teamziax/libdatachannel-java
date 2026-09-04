#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# An explicit destination can be a local Maven repository. Never publishes remotely.
output=${1:-build/development-maven}
output=$(realpath -m "$output")
if test -n "$(git status --porcelain --untracked-files=normal)"; then
  echo 'Refusing an immutable development version from a dirty checkout' >&2
  exit 1
fi
revision=$(git rev-parse HEAD)
version="0.24.1.1-warden.${revision}"
./gradlew jar nativeAdmissionProbe --no-daemon -Plibdatachannel.java-compiler-version=17
python3 - "$output" "$version" <<'PY'
import pathlib, sys, zipfile
output, version = pathlib.Path(sys.argv[1]), sys.argv[2]
root = output / 'dev/ziax/warden/libdatachannel-java' / version
root.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(root / f'libdatachannel-java-{version}.jar', 'w', zipfile.ZIP_DEFLATED) as jar:
    for folder in [pathlib.Path('build/classes/java/main'), pathlib.Path('build/resources/main')]:
        if folder.exists():
            for f in sorted(folder.rglob('*')):
                if f.is_file(): jar.write(f, f.relative_to(folder).as_posix())
with zipfile.ZipFile(root / f'libdatachannel-java-{version}-x86_64.jar', 'w', zipfile.ZIP_DEFLATED) as jar:
    jar.write('build/native-probe/libdatachannel-java.so', 'native/libdatachannel-java.so')
(root / f'libdatachannel-java-{version}.pom').write_text(f'''<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
<groupId>dev.ziax.warden</groupId><artifactId>libdatachannel-java</artifactId><version>{version}</version>
<dependencies><dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.17</version></dependency></dependencies>
</project>\n''')
print(root)
PY
