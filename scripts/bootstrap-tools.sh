#!/usr/bin/env bash
# Bootstrap every external tool SentinelForge depends on.
#
#   ./scripts/bootstrap-tools.sh
#
# pip-installable tools land in the virtualenv. gitleaks ships only as a
# compiled Go binary, so it is fetched from its GitHub release.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$REPO_ROOT/.venv"
PY="${PYTHON:-python3}"

if [[ ! -d "$VENV" ]]; then
  echo "==> Creating virtualenv (.venv)"
  "$PY" -m venv "$VENV"
fi

echo "==> Installing backend + test dependencies"
"$VENV/bin/python" -m pip install --upgrade pip setuptools wheel
"$VENV/bin/python" -m pip install -r "$REPO_ROOT/backend/requirements-dev.txt"

install_gitleaks() {
  if [[ -x "$VENV/bin/gitleaks" ]]; then
    echo "==> gitleaks already present: $("$VENV/bin/gitleaks" version)"
    return
  fi

  local os arch tag asset url
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$(uname -m)" in
    arm64|aarch64) arch="arm64" ;;
    x86_64|amd64)  arch="amd64" ;;
    *) echo "!! Unsupported architecture for gitleaks: $(uname -m)" >&2; return 1 ;;
  esac

  tag="$(curl -sSfL https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
        | grep -m1 '"tag_name"' | cut -d'"' -f4)"
  asset="gitleaks_${tag#v}_${os}_${arch}.tar.gz"
  url="https://github.com/gitleaks/gitleaks/releases/download/${tag}/${asset}"

  echo "==> Fetching gitleaks ${tag} (${os}/${arch})"
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  curl -sSfL -o "$tmp/gitleaks.tar.gz" "$url"
  tar -xzf "$tmp/gitleaks.tar.gz" -C "$tmp" gitleaks
  install -m 0755 "$tmp/gitleaks" "$VENV/bin/gitleaks"
}

install_gitleaks

echo
echo "==> Tool versions"
for tool in bandit semgrep pip-audit gitleaks pytest; do
  if [[ -x "$VENV/bin/$tool" ]]; then
    printf '  %-10s %s\n' "$tool" "$("$VENV/bin/$tool" --version 2>&1 | head -1)"
  else
    printf '  %-10s MISSING\n' "$tool"
  fi
done

echo
echo "==> Docker sandbox"
if "$VENV/bin/python" -c "import docker; docker.from_env().ping()" >/dev/null 2>&1; then
  echo "  reachable -- set SANDBOX_BACKEND=docker"
else
  echo "  NOT reachable -- install Docker and set SANDBOX_BACKEND=docker."
  echo "  The 'local' backend works for demos but is NOT isolated (see docs/SECURITY.md)."
fi

echo
echo "Bootstrap complete. Activate with:  source .venv/bin/activate"
