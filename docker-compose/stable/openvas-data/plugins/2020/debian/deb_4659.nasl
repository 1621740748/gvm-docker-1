# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704659");
  script_version("2021-07-26T11:00:54+0000");
  script_cve_id("CVE-2020-11008");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-26 14:55:00 +0000 (Tue, 26 Jan 2021)");
  script_tag(name:"creation_date", value:"2020-04-21 03:00:10 +0000 (Tue, 21 Apr 2020)");
  script_name("Debian: Security Advisory for git (DSA-4659-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|9)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4659.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4659-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git'
  package(s) announced via the DSA-4659-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Carlo Arenas discovered a flaw in git, a fast, scalable, distributed
revision control system. With a crafted URL that contains a newline or
empty host, or lacks a scheme, the credential helper machinery can be
fooled into providing credential information that is not appropriate for
the protocol in use and host being contacted.");

  script_tag(name:"affected", value:"'git' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (stretch), this problem has been fixed
in version 1:2.11.0-3+deb9u7.

For the stable distribution (buster), this problem has been fixed in
version 1:2.20.1-2+deb10u3.

We recommend that you upgrade your git packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"git", ver:"1:2.20.1-2+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-all", ver:"1:2.20.1-2+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-cvs", ver:"1:2.20.1-2+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-daemon-run", ver:"1:2.20.1-2+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-daemon-sysvinit", ver:"1:2.20.1-2+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-doc", ver:"1:2.20.1-2+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-el", ver:"1:2.20.1-2+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-email", ver:"1:2.20.1-2+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-gui", ver:"1:2.20.1-2+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-man", ver:"1:2.20.1-2+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-mediawiki", ver:"1:2.20.1-2+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-svn", ver:"1:2.20.1-2+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gitk", ver:"1:2.20.1-2+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gitweb", ver:"1:2.20.1-2+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git", ver:"1:2.11.0-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-all", ver:"1:2.11.0-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-arch", ver:"1:2.11.0-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-core", ver:"1:2.11.0-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-cvs", ver:"1:2.11.0-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-daemon-run", ver:"1:2.11.0-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-daemon-sysvinit", ver:"1:2.11.0-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-doc", ver:"1:2.11.0-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-el", ver:"1:2.11.0-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-email", ver:"1:2.11.0-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-gui", ver:"1:2.11.0-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-man", ver:"1:2.11.0-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-mediawiki", ver:"1:2.11.0-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-svn", ver:"1:2.11.0-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gitk", ver:"1:2.11.0-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gitweb", ver:"1:2.11.0-3+deb9u7", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
