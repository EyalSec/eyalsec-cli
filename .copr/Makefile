# Fedora COPR "make srpm" entry point: builds the source RPM from this
# checkout, so a COPR package can follow the repository directly.
#   COPR passes outdir=...; run locally with: make -f .copr/Makefile srpm outdir=/tmp/out
outdir ?= $(CURDIR)/out
spec := packaging/rpm/eyalsec-cli.spec

srpm:
	command -v rpmbuild >/dev/null || dnf -y install rpm-build
	command -v git >/dev/null || dnf -y install git
	git config --global --add safe.directory "$(CURDIR)" || true
	mkdir -p "$(outdir)"
	version=$$(awk '/^Version:/ {print $$2}' $(spec)); \
	git archive --format=tar.gz --prefix=eyalsec-cli-$$version/ -o "$(outdir)/eyalsec-cli-$$version.tar.gz" HEAD
	rpmbuild -bs $(spec) --define "_sourcedir $(outdir)" --define "_srcrpmdir $(outdir)"
