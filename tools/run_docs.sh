#!/usr/bin/env sh

(cd docs; /bin/rm -rf *)
cp index.ts multikey_webcrypto.ts
deno run -A tools/copy_readme.ts
deno doc --html --name="Multikey/WebCrypto API" index.ts
mv multikey_webcrypto.ts index.ts
(cd docs; mv \~ tilde)
deno run -A tools/remove_tilde.ts
