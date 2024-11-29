/* *************************************************************************
Simple tools to put a copy of the README.md file into the module documentation
part of index.ts. By running `deno doc` on the resulting file the generated
documentation will also generate content based on the README.md file
(which is, otherwise, ignored by `deno doc`).

I hope that, at some point, this tools will become unnecessary, and `deno doc`
will be comparable to, say, typedoc...
**************************************************************************** */


const readme: string[] = Deno.readTextFileSync('./README.md').split('\n');
const index: string[] = Deno.readTextFileSync('./index.ts').split('\n');

const result: string[] = [];

for (const indexLine of index) {
    // Locate the anchor for the readme file:
    if (indexLine.startsWith(" * @module")) {
        // copy the content of the readme file, preceded with the documentation mark
        for (const readmeLine of readme) {
            result.push(` * ${readmeLine}`);
        }
    }
    result.push(indexLine);
}

Deno.writeTextFileSync('./index.ts',result.join('\n'));
// console.log(result.join('\n'));

