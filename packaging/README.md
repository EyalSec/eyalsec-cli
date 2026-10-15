# Packaging

Every tagged release already publishes `.deb` and `.rpm` packages, archives for six platforms, `checksums.txt` and build provenance attestations on the [GitHub release](https://github.com/EyalSec/eyalsec-cli/releases), and updates the Homebrew formula in [EyalSec/homebrew-tap](https://github.com/EyalSec/homebrew-tap). This folder holds what the distribution channels that build or host packages themselves need.

`eyalsec-cli` uses only the Go standard library, so none of these builds needs network access or vendored dependencies: Go 1.22 or newer is the only build requirement.

| Path | For |
|---|---|
| `rpm/eyalsec-cli.spec` | Fedora COPR, openSUSE OBS, any `rpmbuild` |
| `../.copr/Makefile` | COPR's "make srpm" method, building straight from this repository |
| `obs/_service` | OBS: fetches the release tarball named in the spec |
| `debian/` | a Launchpad PPA (or any Debian-style build); `debian/build-source.sh` makes the source package |
| `homebrew/formula.sh` | prints the Homebrew formula for a release; the release workflow runs it |
| `cloudsmith/push.sh` | uploads a release's `.deb` and `.rpm` files to Cloudsmith |

When you cut a new version, bump `Version:` and add a `%changelog` entry in the spec, and add an entry at the top of `debian/changelog`.

## Fedora COPR

1. Sign in at <https://copr.fedorainfracloud.org> with a Fedora account.
2. **New project**: name `eyalsec-cli`; chroots: the current `fedora-*`, `epel-9` and `epel-10` for `x86_64` and `aarch64`. Leave "Enable internet access during builds" off; the build does not need it.
3. In the project, **Packages > New package > SCM**:
   - Clone URL: `https://github.com/EyalSec/eyalsec-cli.git`
   - Committish: the release tag, such as `v0.1.0`
   - Spec file: `packaging/rpm/eyalsec-cli.spec`
   - Build SRPM with: **make srpm**
   - Package name: `eyalsec-cli`
4. **Rebuild**. Users then install with:

   ```bash
   sudo dnf copr enable <your-copr-user>/eyalsec-cli
   sudo dnf install eyalsec-cli
   ```

From the command line instead: `copr-cli create eyalsec-cli --chroot fedora-rawhide-x86_64 ...`, then `make -f .copr/Makefile srpm outdir=/tmp/srpm` and `copr-cli build eyalsec-cli /tmp/srpm/*.src.rpm`.

## openSUSE Build Service (OBS)

1. Sign in at <https://build.opensuse.org> and install `osc`.
2. Create the package in your home project and add the two files:

   ```bash
   osc checkout home:<your-obs-user>
   cd home:<your-obs-user>
   osc mkpac eyalsec-cli && cd eyalsec-cli
   cp <this repo>/packaging/rpm/eyalsec-cli.spec <this repo>/packaging/obs/_service .
   osc add eyalsec-cli.spec _service
   osc commit -m "eyalsec-cli 0.1.0"
   ```

3. In the web UI, **Repositories > Add from a distribution**: openSUSE Tumbleweed, openSUSE Leap 15.6 and any Fedora or RHEL targets you want. The `_service` downloads the release tarball named in the spec's `Source0`.
4. Users install from the repository OBS shows on the package page (**Download package**).

## Launchpad PPA (Ubuntu)

1. Create a Launchpad account, upload your OpenPGP key to it, and create a PPA named `eyalsec` (**Create a new PPA** on your profile page).
2. On an Ubuntu machine with `devscripts`, `debhelper`, `dpkg-dev` and `git`, build and sign one source package per Ubuntu release:

   ```bash
   packaging/debian/build-source.sh 0.1.0 noble
   debsign -k <your key id> ../build-deb/*_source.changes
   dput ppa:<launchpad-user>/eyalsec ../build-deb/*_source.changes
   ```

   Repeat with `jammy` only if that release's `golang-go` is 1.22 or newer (24.04 `noble` and later have it).
3. Launchpad builds `amd64` and `arm64` binaries. Users then install with:

   ```bash
   sudo add-apt-repository ppa:<launchpad-user>/eyalsec
   sudo apt install eyalsec-cli
   ```

## Cloudsmith

1. Create a Cloudsmith account and an organisation `eyalsec` with a repository `eyalsec-cli`. Cloudsmith offers open-source projects a hosted plan on application; otherwise pick a plan that fits.
2. Copy your API key (**User settings > API key**) and upload a release:

   ```bash
   pip install cloudsmith-cli
   CLOUDSMITH_API_KEY=... packaging/cloudsmith/push.sh 0.1.0 eyalsec/eyalsec-cli
   ```

3. The repository's **Set Me Up** page gives users the one-line `apt` and `dnf` setup.
