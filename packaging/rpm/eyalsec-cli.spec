# RPM spec for Fedora COPR, openSUSE OBS and any rpmbuild.
# eyalsec-cli uses only the Go standard library, so the build needs no
# network access and no vendored dependencies.

%global debug_package %{nil}

Name:           eyalsec-cli
Version:        0.1.0
Release:        1%{?dist}
Summary:        Command-line client for the EyalSec API
License:        MIT
URL:            https://github.com/EyalSec/eyalsec-cli
Source0:        https://github.com/EyalSec/eyalsec-cli/archive/refs/tags/v%{version}.tar.gz#/%{name}-%{version}.tar.gz

%if 0%{?suse_version}
BuildRequires:  go >= 1.22
%else
BuildRequires:  golang >= 1.22
%endif

# The API is reached over https, which needs the system's CA bundle.
Requires:       ca-certificates

%description
eyalsec-cli reads your EyalSec security events and machines from a terminal,
a cron job or a CI step. It lists and searches events, shows one event's full
detail, exports matching events as CSV or JSON, and lists machines and runs,
through the EyalSec API. A read-only API key is enough.

%prep
%autosetup -n %{name}-%{version}

%build
export CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=off GOFLAGS="-trimpath -mod=readonly"
export GOCACHE="$PWD/.gocache" GOPATH="$PWD/.gopath"
go build -ldflags "-s -w -X eyalsec.com/cli/internal/cli.version=v%{version}" -o eyalsec-cli ./cmd/eyalsec-cli

%check
export CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=readonly
export GOCACHE="$PWD/.gocache" GOPATH="$PWD/.gopath"
go test ./...
./eyalsec-cli version | grep -q "v%{version}"

%install
install -Dpm 0755 eyalsec-cli %{buildroot}%{_bindir}/eyalsec-cli

%files
%license LICENSE
%doc README.md
%{_bindir}/eyalsec-cli

%changelog
* Thu Oct 15 2026 Eyal Gabay <eyal@eyalsec.com> - 0.1.0-1
- First release
