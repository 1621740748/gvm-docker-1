# Copyright (C) 2018 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.891400");
  script_version("2020-01-29T08:28:43+0000");
  script_name("Debian LTS: Security Advisory for tomcat7 (DLA-1400-2)");
  script_tag(name:"last_modification", value:"2020-01-29 08:28:43 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2018-07-10 00:00:00 +0200 (Tue, 10 Jul 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/07/msg00001.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_tag(name:"affected", value:"tomcat7 on Debian Linux");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', this issue has been fixed in version
7.0.56-3+really7.0.88-2.

We recommend that you upgrade your tomcat7 packages.");

  script_tag(name:"summary", value:"The security update of Tomcat 7 announced as DLA-1400-1 introduced a
regression for applications that make use of the Equinox OSGi
framework. The MANIFEST file of tomcat-jdbc.jar in libtomcat7-java
contains an invalid version number which was automatically derived
from the Debian package version. This caused an OSGi exception.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libservlet3.0-java", ver:"7.0.56-3+really7.0.88-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libservlet3.0-java-doc", ver:"7.0.56-3+really7.0.88-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtomcat7-java", ver:"7.0.56-3+really7.0.88-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat7", ver:"7.0.56-3+really7.0.88-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat7-admin", ver:"7.0.56-3+really7.0.88-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat7-common", ver:"7.0.56-3+really7.0.88-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat7-docs", ver:"7.0.56-3+really7.0.88-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat7-examples", ver:"7.0.56-3+really7.0.88-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat7-user", ver:"7.0.56-3+really7.0.88-2", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
