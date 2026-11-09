# Supplied payload lists

Five text collections supplied by Victor on 2026-11-09. The original upstream origin and license were not specified. These files are separate from the pinned mini-tricky payloads in `third-party/mini-tricky/payloads/`.

| File | Supplied category | Lines | Bytes |
| --- | --- | ---: | ---: |
| [lfi.txt](lfi.txt) | Local file inclusion / traversal | 9,477 | 509,549 |
| [rce_payloads.txt](rce_payloads.txt) | Command injection / RCE | 519 | 21,789 |
| [sqli.txt](sqli.txt) | SQL injection | 144 | 4,385 |
| [ssti.txt](ssti.txt) | Server-side template injection | 52 | 4,190 |
| [xss.txt](xss.txt) | Cross-site scripting | 68 | 3,039 |

The files are byte-for-byte copies of the uploads. Ordering, duplicates, trailing spaces, UTF-8 characters, encodings and the original final-newline state are preserved. Category names describe the supplied lists; entries have not been validated, repaired or reclassified. Some entries contain fixed callback addresses, placeholders, file reads, commands or timing delays; review the selected entries for the intended test.

## Select a list in the application

1. Open **Local workspace → Inputs** and register the absolute path to the chosen file in this checkout, such as `/absolute/path/to/AI-tricky/payloads/xss.txt`.
2. Select that registered file on a **Wordlist** source node, or through an adapter's **Wordlist** input binding where supported.
3. Use the existing workflow preflight and run controls. Registering a list does not execute it or send requests.

A registered file binding copies the original file into the job directory and pins its contents. Normal downstream tool behavior still applies. The built-in **Payload** category node continues to use the existing pinned mini-tricky lists; these new collections are not substituted automatically. For standalone binaries, keep the desired file as an external input and register its absolute path.

## Verify the copies

From the repository root:

```bash
(cd payloads && sha256sum -c SHA256SUMS)
```

[`SHA256SUMS`](SHA256SUMS) records SHA-256 digests of the uploaded bytes. Git attributes disable line-ending conversion for these text files. If you curate or deduplicate entries later, keep the original collection and record the derived list separately.
