# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.704556");
  script_version("2020-01-14T08:22:37+0000");
  script_cve_id("CVE-2019-18281");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-01-14 08:22:37 +0000 (Tue, 14 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-11-02 03:00:07 +0000 (Sat, 02 Nov 2019)");
  script_name("Debian Security Advisory DSA 4556-1 (qtbase-opensource-src - security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4556.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4556-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qtbase-opensource-src'
  package(s) announced via the DSA-4556-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out-of-bounds memory access was discovered in the Qt library, which
could result in denial of service through a text file containing many
directional characters.

The oldstable distribution (stretch) is not affected.");

  script_tag(name:"affected", value:"'qtbase-opensource-src' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), this problem has been fixed in
version 5.11.3+dfsg1-1+deb10u1.

We recommend that you upgrade your qtbase-opensource-src packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libqt5concurrent5", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5core5a", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5dbus5", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5gui5", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5network5", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5opengl5", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5opengl5-dev", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5printsupport5", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5-ibase", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5-mysql", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5-odbc", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5-psql", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5-sqlite", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5-tds", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5test5", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5widgets5", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5xml5", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qt5-default", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qt5-flatpak-platformtheme", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qt5-gtk-platformtheme", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qt5-qmake", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qt5-qmake-bin", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qtbase5-dev", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qtbase5-dev-tools", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qtbase5-doc", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qtbase5-doc-html", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qtbase5-examples", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qtbase5-private-dev", ver:"5.11.3+dfsg1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);