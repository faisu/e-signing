# Bundled CA certificates

Files in this directory are baked into the native host binary at compile time
(see `build.rs`). The host walks issuer→subject DNs to attach intermediate and
root CAs to the CMS signature so Adobe can build a trust chain back to a root
in its trust list.

## What to put here

Drop DER-encoded CA certificates as `.der`, `.cer`, or `.crt`. PEM is **not**
supported — convert with `openssl x509 -in foo.pem -outform der -out foo.der`
first. Filenames don't matter; chain matching is by Distinguished Name.

After adding or replacing files, rebuild the native host:

```
npm run build:release
```

`build.rs` re-runs whenever this directory changes, so cargo picks up new files
automatically.

## eMudhra Class 3 individual DSC chain

Required files for typical eMudhra DSCs (HYP2003, ePass2003, etc.) issued
to Indian individuals/professionals after 2022:

1. **e-Mudhra Sub CA for Class 3 Individual 2022** (intermediate)
2. **e-Mudhra Root CA** (intermediate, signs the Sub CAs)
3. **CCA India 2022** (self-signed root; bridges to Adobe's AATL trust)

Download the latest published versions from eMudhra's official repository:

- https://www.e-mudhra.com/repository.html → "Cross Certificates" /
  "Sub CA Certificates" sections
- Or directly from CCA India's published trust list at
  https://cca.gov.in/repository.html

Download files in DER form (the page exposes both PEM and DER; pick DER).
If the cert downloads as PEM only, convert as above.

## Other CAs

To support Sify, Capricorn, NSDL e-Gov, IDsign, Vsign, etc., download the
appropriate intermediate(s) and root from each CA's published repository
and drop them in this directory. The chain walker is CA-agnostic — it
matches purely by issuer/subject DN.

## What's intentionally NOT here

- **Private keys** — never put any private material here.
- **PEM bundles** — split into individual DER files first.
- **Untrusted/test certs in production builds** — anything in this directory
  becomes part of every signature this build emits. Treat the contents as
  part of the signed artifact.
