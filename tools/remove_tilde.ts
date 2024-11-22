// Import necessary modules
import { walk } from "jsr:@std/fs/walk";

// Define the action to be performed on each HTML file
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
