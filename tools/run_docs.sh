#!/usr/bin/env sh
# shellcheck disable=SC2164
(cd docs; /bin/rm -rf *)
cp index.ts multikey_webcrypto.ts
deno run -A tools/copy_readme.ts
deno doc --html --name="Multikey/WebCrypto API" index.ts lib/*
mv multikey_webcrypto.ts index.ts
(cd docs; touch .nojekyll)
