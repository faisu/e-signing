# Native Host Installation

Host name: `com.example.autodcr.signer`

## 1) Build host

```bash
cd native-host
npm install
npm run build
```

## 2) Prepare launcher path

Pick launcher by OS:

- macOS: `native-host/launchers/macos.sh`
- Linux: `native-host/launchers/linux.sh`
- Windows: `native-host/launchers/windows.bat`

Use an absolute path in the manifest `path` field.

For macOS/Linux:

```bash
chmod +x native-host/launchers/macos.sh native-host/launchers/linux.sh
```

## 3) Configure host manifest

Template: `native-host/manifests/com.example.autodcr.signer.json`

Replace:

- `<ABSOLUTE_PATH_TO_LAUNCHER>`
- `<EXTENSION_ID_PLACEHOLDER>`

`allowed_origins` must contain:

```json
["chrome-extension://<YOUR_EXTENSION_ID>/"]
```

## 4) Install native manifest by OS

### macOS

Copy to:

`~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.example.autodcr.signer.json`

### Linux

Copy to:

`~/.config/google-chrome/NativeMessagingHosts/com.example.autodcr.signer.json`

### Windows

1. Copy manifest JSON to a stable location.
2. Create registry key:

`HKCU\Software\Google\Chrome\NativeMessagingHosts\com.example.autodcr.signer`

3. Set default value to full path of the manifest JSON file.

## 5) Verify

1. Load extension unpacked from `dist/`.
2. Open allowed web origin.
3. Send a `PING` bridge request.
4. Verify response includes host version and `ok: true`.
