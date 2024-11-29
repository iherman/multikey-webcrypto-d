/**********************************************************************************************************
 Simple tools to exchange the '~' character in the URLs generated by deno doc into the HTML file
 for its proper URL encoded variant ('&x#7e;'). It seems that the documentation cannot be displayed on,
 e.g., GitHub.io. Maybe this change will make it possible.

 I hope that, at some point, this tools will become unnecessary, and `deno doc`
 will be comparable to, say, typedoc...
 ***********************************************************************************************************/

// Import necessary modules
import { walk } from "jsr:@std/fs/walk";

// Define the action to be performed on each HTML file
// deno-lint-ignore require-await
async function processHtmlFile(filePath: string) {
    // console.log(`Processing file: ${filePath}`);
    const content: string = Deno.readTextFileSync(filePath);
    const newContent = content.replaceAll("&#x2F;~&#x2F;", "&#x2F;&#x7E;&#x2F;");
    // console.log(newContent);
    Deno.writeTextFileSync(filePath, newContent);
}

// Walk through directories starting from the current directory
for await (const entry of walk("./docs", { exts: [".html"], includeFiles: true, includeDirs: false })) {
    await processHtmlFile(entry.path);
}
