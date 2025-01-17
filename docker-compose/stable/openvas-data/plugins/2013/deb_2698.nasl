# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 2698-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702698");
  script_version("2020-10-05T06:02:24+0000");
  script_cve_id("CVE-2013-1960", "CVE-2013-1961");
  script_name("Debian Security Advisory DSA 2698-1 (tiff - buffer overflow)");
  script_tag(name:"last_modification", value:"2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)");
  script_tag(name:"creation_date", value:"2013-06-18 00:00:00 +0200 (Tue, 18 Jun 2013)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2698.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"tiff on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (squeeze), these problems have been fixed in
version 3.9.4-5+squeeze9.

For the stable distribution (wheezy), these problems have been fixed in
version 4.0.2-6+deb7u1.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 4.0.2-6+nmu1.

We recommend that you upgrade your tiff packages.");
  script_tag(name:"summary", value:"Multiple issues were discovered in the TIFF tools, a set of utilities for
TIFF image file manipulation and conversion.

CVE-2013-1960
Emmanuel Bouillon discovered a heap-based buffer overflow in the
tp_process_jpeg_strip function in the tiff2pdf tool. This could
potentially lead to a crash or arbitrary code execution.

CVE-2013-1961
Emmanuel Bouillon discovered many stack-based buffer overflows in
the TIFF tools. These issues could potentially lead to a crash or
arbitrary code execution.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libtiff-doc", ver:"3.9.4-5+squeeze9", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff-opengl", ver:"3.9.4-5+squeeze9", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff-tools", ver:"3.9.4-5+squeeze9", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff4", ver:"3.9.4-5+squeeze9", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff4-dev", ver:"3.9.4-5+squeeze9", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiffxx0c2", ver:"3.9.4-5+squeeze9", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff-doc", ver:"4.0.2-6+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff-opengl", ver:"4.0.2-6+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff-tools", ver:"4.0.2-6+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff5", ver:"4.0.2-6+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff5-alt-dev", ver:"4.0.2-6+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff5-dev", ver:"4.0.2-6+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiffxx5", ver:"4.0.2-6+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
