/* *************************************************************************
Simple tools to put a copy of the README.md file into the module documentation
part of index.ts. By running `deno doc` on the resulting file the generated
documentation will also generate content based on the README.md file
(which is, otherwise, ignored by `deno doc`).

I hope that, at some point, this tools will become unnecessary, and `deno doc`
will be comparable to, say, typedoc...
**************************************************************************** */

interface Args {
    readme :string;
    index :string;
    indexAnchor: string;
    name: string;
}

const README: string = "README.md";
const INDEX_ANCHOR: string = " * @module";
const EXTRAS: string = "lib/*"

const deno_json = JSON.parse(Deno.readTextFileSync("deno.json"));

const args: Args = {
    readme: README,
    index: deno_json.exports,
    indexAnchor: INDEX_ANCHOR,
    name: deno_json.name,
}

function copy_readme() {
    const readme: string[] = Deno.readTextFileSync(args.readme).split('\n');
    const index: string[] = Deno.readTextFileSync(args.index).split('\n');

    const result: string[] = [];
    for (const indexLine of index) {
        // Locate the anchor for the readme file:
        if (indexLine.startsWith(args.indexAnchor)) {
            // copy the content of the readme file, preceded with the documentation mark
            for (const readmeLine of readme) {
                result.push(` * ${readmeLine}`);
            }
        }
        result.push(indexLine);
    }

    Deno.writeTextFileSync(args.index, result.join('\n'));
}

function doc() {
    // Define the command to run 'deno doc'
    const command = new Deno.Command(Deno.execPath(),
        {
        args: [
            'doc',
            '--html',
            `--name="${args.name}"`,
            args.index,
            EXTRAS,
        ],
    });

    // Execute the command and collect output
    const { code, stdout, stderr } = command.outputSync();
    // Check if the command was successful
    if (code !== 0) {
        console.error(new TextDecoder().decode(stderr)); // Print any errors
    } else {
        console.log(new TextDecoder().decode(stdout));
    }
}

const tempFile = Deno.makeTempFileSync({suffix: ".ts"});
Deno.copyFileSync(args.index,tempFile);
copy_readme();
doc();
Deno.copyFileSync(tempFile, args.index);
Deno.removeSync(tempFile);
Deno.writeTextFileSync("./docs/.nojekyll", "");
