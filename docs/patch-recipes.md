# Patch recipes

`uat patch plan recipe.json --root DIR` validates every rule and prints the proposed hashes/diffs. `uat patch apply recipe.json --root DIR --out NEW_DIR` validates again and copies the input before changing files. No approval prompt is needed; running `apply` requests that operation.

Paths are exact, relative POSIX paths inside the input directory. Output must be outside the input tree. Symlinks are rejected. Each rule requires `expected_matches`, a positive integer. A mismatch stops the entire operation before output is created. Optional `sha256` checks the file as it exists immediately before that rule, including earlier edits in the same recipe.

```json
{
  "version": 1,
  "changes": [
    {
      "path": "assets/settings.json",
      "kind": "text_replace",
      "find": "\"language\": \"en\"",
      "replace": "\"language\": \"fr\"",
      "expected_matches": 1
    },
    {
      "path": "AndroidManifest.xml",
      "kind": "xml_set_attribute",
      "xpath": "./application",
      "attribute": "android:label",
      "expected": "@string/app_name",
      "value": "My Build",
      "expected_matches": 1
    }
  ]
}
```

Supported kinds:

| Kind | Required values | Behavior |
| --- | --- | --- |
| `text_replace` | `find`, `replace` | Exact UTF-8 text replacement; multiple matches require the matching count |
| `bytes_replace` | `find`, `replace` as hex | Exact byte replacement throughout the selected file, with equal byte lengths |
| `binary_patch` | `offset`, `find`, `replace` | One equal-length patch at a file offset; offset can be an integer or `"0x1000"` |
| `xml_set_attribute` | `xpath`, `attribute`, `expected`, `value` | Updates matching elements in decoded XML; use `expected: null` for a previously absent attribute |

XML uses Python ElementTree's XPath subset and the `android` namespace. XML serialization can change whitespace and namespace prefixes. Binary AndroidManifest.xml must first be decoded through Apktool; recipe XML edits operate on text XML.

Edits are limited to 128 MiB per file and 256 MiB across changed files. For larger native files use the streaming `binary patch` command. Native byte patches require knowledge of the binary format and instruction set; equal length alone does not establish correct behavior.

Recipes do not rebuild or sign automatically. Run `apk build` and `apk sign`, or apply a recipe to a copied whole toolkit project and run `project rebuild` on that copy. The toolkit records the patch report and preserves the source.
