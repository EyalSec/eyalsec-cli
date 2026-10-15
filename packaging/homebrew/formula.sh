#!/usr/bin/env bash
# Print the Homebrew formula for one release.
#
#   packaging/homebrew/formula.sh 0.1.0 checksums.txt > Formula/eyalsec-cli.rb
#
# checksums.txt is the file GoReleaser attaches to the GitHub release.
set -euo pipefail

if [ $# -ne 2 ]; then
  echo "usage: $0 VERSION CHECKSUMS_FILE" >&2
  exit 2
fi
version=$1
sums=$2
case "$version" in
  v*) echo "VERSION is the bare number, without the v (got $version)" >&2; exit 2 ;;
esac

sha() {
  local file="eyalsec-cli_${version}_$1.tar.gz"
  local s
  s=$(awk -v f="$file" '$2 == f { print $1 }' "$sums")
  if [ -z "$s" ]; then
    echo "$file is not in $sums" >&2
    exit 1
  fi
  echo "$s"
}

base="https://github.com/EyalSec/eyalsec-cli/releases/download/v${version}"

cat <<RUBY
class EyalsecCli < Formula
  desc "Read your EyalSec security events and machines from the terminal"
  homepage "https://eyalsec.com"
  version "${version}"
  license "MIT"

  on_macos do
    on_arm do
      url "${base}/eyalsec-cli_${version}_darwin_arm64.tar.gz"
      sha256 "$(sha darwin_arm64)"
    end
    on_intel do
      url "${base}/eyalsec-cli_${version}_darwin_amd64.tar.gz"
      sha256 "$(sha darwin_amd64)"
    end
  end

  on_linux do
    on_arm do
      url "${base}/eyalsec-cli_${version}_linux_arm64.tar.gz"
      sha256 "$(sha linux_arm64)"
    end
    on_intel do
      url "${base}/eyalsec-cli_${version}_linux_amd64.tar.gz"
      sha256 "$(sha linux_amd64)"
    end
  end

  def install
    bin.install "eyalsec-cli"
  end

  test do
    assert_match "eyalsec-cli v#{version}", shell_output("#{bin}/eyalsec-cli version")
    ENV["EYALSEC_CONFIG"] = testpath/"config"
    output = shell_output("#{bin}/eyalsec-cli whoami 2>&1", 1)
    assert_match "no API key found", output
  end
end
RUBY
