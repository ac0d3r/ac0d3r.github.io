## Go-Embed

Starting from Go 1.16, the language introduced the `go:embed` directive, providing native support for embedding static files.
Embedded files can be accessed via an `embed.FS` pseudo-filesystem. They are read-only and packaged directly within the compiled binary.

## Understanding How Go-Embed Works

The `embed.FS` file container structure:

```go
type FS struct {
    files *[]file
}
type file struct {
    name string   // file name
    data string  // file content
    hash [16]byte // truncated SHA256 hash
}
```

---

- The demo directory structure:

```
tests
├── embedemo.go
└── misc
    ├── bdir
    │   └── sample.txt
    ├── sample.txt
    └── sample2.txt
```

- `embedemo.go`:

```go
package main
import (
    "embed"
    "fmt"
    "log"
)

//go:embed misc
var embedFiles embed.FS
func main() {
    content, err := embedFiles.ReadFile("misc/sample.txt")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(string(content))
}
```

Use debugging to inspect what contents are stored in the files after compilation：

<img height="200" src="https://github.com/user-attachments/assets/b8a49d08-a841-4b3f-8258-81d3a5cccc65" />

`//go:embed <filename>` is a compiler directive. During `go build`, it triggers the [`WriteEmbed`](https://github.com/golang/go/blob/master/src/cmd/compile/internal/staticdata/embed.go#L134-L171) function to process the directive:


<img height="530" src="https://github.com/user-attachments/assets/c52c93c2-0ce2-4807-84ef-d630ba20d289" />

- `L138-L140`: `slicedata` is the pointer to `FS.files`, writing the length of `files` twice;  
- `L150`: writes the filename (pointer);  
- `L152-156`: filenames ending with `/` are directories, skipped, with `data` and `hash` set to 0;  
- `L158-164`: writes `data` (pointer) and `hash` (16 bytes);

## Analyzing with Decompiler Tools

In the `main` function, calling `embed.FS.ReadFile`
- `x1` refers to the string `"misc/sample.txt"`
- `x0` is the pointer to the `FS`.

<img height="71" src="https://github.com/user-attachments/assets/6968653a-99f2-4b01-86c8-e84f9e214dbd" />

Locate .rodata and display it using a hex viewer:

<img height="200" src="https://github.com/user-attachments/assets/e8654cfc-a150-4145-9bc6-cfa6f1a4a39b" />

* The three bytes marked in red represent the `files` pointer (little-endian), the length, and the length again.
* The first blue box, spanning six bytes, represents the directory structure: filename pointer, filename length, data pointer, data length, and a 2-byte hash. Since this is a directory, `data` and `hash` are empty.
* The second blue box highlights the structure of a file that contains actual content.

The files studied above are Mach-O for the ARM64 architecture. Later, I also compiled ELF and PE binaries, and their storage structures are the same. You can use the `debug/*` packages to parse files for each architecture, convert virtual addresses to file offsets, and thus extract the embedded files.

## Building an Automated Tool

It has been open-sourced and can extract embedded files from PE, ELF, and Mach-O binaries: [BreakOnCrash/go-embed-extractor](https://github.com/BreakOnCrash/go-embed-extractor).

~~The downside is that you have to manually locate the FS pointer 😅~~

[@leonjza](https://x.com/leonjza) shared a [method](https://x.com/leonjza/status/1960794001449025797) using the radare tool to find the FS structure pointer, which can then be combined with [go-embed-extractor](https://github.com/BreakOnCrash/go-embed-extractor) to extract embedded files.

<img height="216" src="https://github.com/user-attachments/assets/a90dc3f1-43cd-4157-91b9-457b1592fcdb" />

## Reference Links

- [extracting-go-embeds](https://web.archive.org/web/20230606135339/https://0x00sec.org/t/extracting-go-embeds/34885)
- [use-radare-extract-go-embeds](https://x.com/leonjza/status/1960794001449025797)