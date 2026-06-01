# Scanner image for re-recording the oscap fixture from a REAL OpenSCAP run.
# Build:  docker build -t oscap-runner .
# The image carries openscap-scanner (the `oscap` CLI) and scap-security-guide
# (the SSG SCAP content, including ssg-almalinux9-ds.xml). A real scan is then
# run against the AlmaLinux 9 datastream's "standard" profile to produce the
# XCCDF results XML that IS the fixture product. See ../record.sh.
FROM almalinux:9
RUN dnf install -y openscap-scanner scap-security-guide && dnf clean all
