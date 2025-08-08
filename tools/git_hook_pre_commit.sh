KEY_NAME="cic-my-sign-key"
CERT_FILE="commit-signer.crt"
ZIP_FILE="commit-snapshot.zip"
SIGNATURE_FILE="commit-snapshot.zip.sig"

# Ellenőrzések (A Vault indítását és token meglétét feltételezzük)
# ...
if [[ -f "$XDG_RUNTIME_DIR/vault/vault.pid" ]]; then
    PID=$(cat "$XDG_RUNTIME_DIR/vault/vault.pid")

    if ps -p "$PID" > /dev/null 2>&1 && pgrep -x vault | grep -q "^$PID$"; then
        # Process fut → nézzük, tényleg él-e a Vault CLI szerint
        if vault status >/dev/null 2>&1; then
            echo "[!] Vault is running with PID $PID – stop it first."
            exit 0
        else
            echo "[*] PID file exists and process is running, but Vault is not responding."
            exit 1
        fi
    else
        echo "[*] Stale vault.pid found (no running Vault process with PID $PID)."
        rm -f "$XDG_RUNTIME_DIR/vault/vault.pid"
    fi
fi

# Létrehozza a ZIP-archívumot a staging area-ból
echo "[*] ZIP archívum létrehozása a staging area-ból..."
if ! TREE_ID=$(git write-tree); then
  echo "Hiba: A staging area üres vagy nem érvényes."
  exit 1
fi
tmpdir=$(mktemp -d)
ZIP_HASH=$(git archive --format=tar "$TREE_ID" | tar -xf - -C "$tmpdir" && \
> tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner   -cf - -C "$tmpdir" . | sha256sum)
rm -rf "$tmpdir"

# Aláírás kérése a Vault-tól (Transit Secrets Engine)
SIGNATURE=$(vault write -format=json transit/sign/$KEY_NAME \
  digest_input="$ZIP_HASH" \
  algorithm=sha256 \
  prehashed=true | jq -r .data.signature)

if [[ -z "$SIGNATURE" ]]; then
  echo "Hiba: Hiba történt a ZIP-fájl aláírása során."
  exit 1
fi

# Aláírás fájlba írása
{
  echo ""
  echo "---"
  echo "[signing-metadata]"
  echo "key = $KEY_NAME"
  echo "signature = $SIGNATURE"
  echo "hash-algorithm = sha256"
  echo "digest = $ZIP_HASH"

  echo ""
  echo "[certificate]"
  echo "$CERT"  # már szétszedve sed-del, hogy valódi PEM legyen
} >> "$COMMIT_MSG_FILE"


echo "$SIGNATURE" > "$SIGNATURE_FILE"
