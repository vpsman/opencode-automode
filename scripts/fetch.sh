#!/bin/sh
# Downloads llama.cpp's CPU build and the Kev decision model, checking each SHA-256.
# Installs under $OPENCODE_AUTOMODE_HOME (default ~/.local/share/opencode-automode), which is
# where systemd/opencode-automode-kev.service expects them. Re-running skips what is present
# and intact: a model file already there is checked against its SHA-256 again and replaced if
# it does not match. (The unpacked llama.cpp tree cannot be re-checked: only the archive has a
# published hash. Delete $OPENCODE_AUTOMODE_HOME/llama to fetch it again.)
#   scripts/fetch.sh          Kev-0.8B (774 MB, the default model)
#   scripts/fetch.sh --4b     also Kev-4B (4.5 GB, for benchmarking; slower, not more accurate)
set -eu
HOME_DIR=${OPENCODE_AUTOMODE_HOME:-$HOME/.local/share/opencode-automode}
LLAMA_BUILD=b12283
LLAMA_SHA256=5f24a62b84a37c186efd1e3e1d77bfad3a1772d9aa35bfcc9e1572723d0c4faf

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) ;;
  *) echo "fetch.sh: only Linux x86_64 is scripted; get llama-server $LLAMA_BUILD for your platform from https://github.com/ggml-org/llama.cpp/releases" >&2; exit 1 ;;
esac

mkdir -p "$HOME_DIR/llama" "$HOME_DIR/models"
if [ ! -x "$HOME_DIR/llama/$LLAMA_BUILD/llama-$LLAMA_BUILD/llama-server" ]; then
  cd "$HOME_DIR/llama"
  curl -fsSL -o llama.tgz "https://github.com/ggml-org/llama.cpp/releases/download/$LLAMA_BUILD/llama-$LLAMA_BUILD-bin-ubuntu-x64.tar.gz"
  echo "$LLAMA_SHA256  llama.tgz" | sha256sum -c -
  mkdir -p "$LLAMA_BUILD" && tar -xzf llama.tgz -C "$LLAMA_BUILD" && rm llama.tgz
fi

get() { # repo file sha256
  if [ -f "$HOME_DIR/models/$2" ]; then
    if (cd "$HOME_DIR/models" && echo "$3  $2" | sha256sum -c - >/dev/null 2>&1); then return 0; fi
    echo "fetch.sh: $2 does not match its SHA-256, downloading it again" >&2
    rm -f "$HOME_DIR/models/$2"
  fi
  curl -fsSL -o "$HOME_DIR/models/$2.part" "https://huggingface.co/$1/resolve/main/$2"
  (cd "$HOME_DIR/models" && echo "$3  $2.part" | sha256sum -c - && mv "$2.part" "$2")
}
get ggml-org/Kev-0.8B-GGUF Kev-0.8B-Q8_0.gguf 27278f34eb3273bceea4c053dc50dd61a5161da21a718c4aacdf8fd5830771d0
if [ "${1:-}" = "--4b" ]; then
  get ggml-org/Kev-4B-GGUF Kev-4B-Q8_0.gguf 7c2ebed90560522c2801389db482ac1dc4c36d828f201f6074c1d60e433948da
fi
echo "fetch.sh: done ($HOME_DIR)"
