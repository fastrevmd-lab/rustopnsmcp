# Example inventory

`devices.example.json` shows the shape `rustopnsmcp` expects for its device
inventory (`--device-mapping`, default `devices.json`).

Copy it into place, then:

- Replace `fw-1` with a name for your OPNsense device.
- Set `endpoint` to the device's `https://` GUI/API address.
- Export `OPNSENSE_FW_1_API_KEY` and `OPNSENSE_FW_1_API_SECRET` with the key
  pair from **System > Access > Users > <user> > API keys**, or point
  `api_key_file`/`api_secret_file` at owner-only (mode 0600) files instead.
- If the device presents a certificate from a private CA, set `ca_pem_path`
  to that CA's PEM file. There is no insecure-skip-verify option anywhere in
  this server: a private CA is the only way to reach such a device.
- `chmod 600 devices.json` and make sure it is owned by the service user —
  the loader refuses anything looser.
