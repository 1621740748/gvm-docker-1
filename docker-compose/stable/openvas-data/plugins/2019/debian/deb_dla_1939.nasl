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
  script_oid("1.3.6.1.4.1.25623.1.0.891939");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2018-20650", "CVE-2018-21009", "CVE-2019-12493");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-10-01 02:00:10 +0000 (Tue, 01 Oct 2019)");
  script_name("Debian LTS: Security Advisory for poppler (DLA-1939-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/09/msg00033.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1939-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler'
  package(s) announced via the DLA-1939-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues in poppler, a PDF rendering library, have been fixed.

CVE-2018-20650

A missing check for the dict data type could lead to a denial of
service.

CVE-2018-21009

An integer overflow might happen in Parser::makeStream.

CVE-2019-12493

A stack-based buffer over-read by a crafted PDF file might happen in
PostScriptFunction::transform because some functions mishandle tint
transformation.");

  script_tag(name:"affected", value:"'poppler' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
0.26.5-2+deb8u11.

We recommend that you upgrade your poppler packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"gir1.2-poppler-0.18", ver:"0.26.5-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-cpp-dev", ver:"0.26.5-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-cpp0", ver:"0.26.5-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-dev", ver:"0.26.5-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-glib-dev", ver:"0.26.5-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-glib-doc", ver:"0.26.5-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-glib8", ver:"0.26.5-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-private-dev", ver:"0.26.5-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-qt4-4", ver:"0.26.5-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-qt4-dev", ver:"0.26.5-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-qt5-1", ver:"0.26.5-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-qt5-dev", ver:"0.26.5-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler46", ver:"0.26.5-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"poppler-dbg", ver:"0.26.5-2+deb8u11", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"poppler-utils", ver:"0.26.5-2+deb8u11", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
