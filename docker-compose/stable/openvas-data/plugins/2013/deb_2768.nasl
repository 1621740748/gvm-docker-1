# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 2768-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.702768");
  script_version("2021-07-05T02:00:48+0000");
  script_cve_id("CVE-2013-4349", "CVE-2012-4540");
  script_name("Debian Security Advisory DSA 2768-1 (icedtea-web - heap-based buffer overflow)");
  script_tag(name:"last_modification", value:"2021-07-05 02:00:48 +0000 (Mon, 05 Jul 2021)");
  script_tag(name:"creation_date", value:"2013-10-04 00:00:00 +0200 (Fri, 04 Oct 2013)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2768.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"icedtea-web on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), this problem has been fixed in
version 1.4-3~deb7u2.

For the unstable distribution (sid), this problem has been fixed in
version 1.4-3.1.

We recommend that you upgrade your icedtea-web packages.");
  script_tag(name:"summary", value:"A heap-based buffer overflow vulnerability was found in icedtea-web, a
web browser plugin for running applets written in the Java programming
language. If a user were tricked into opening a malicious website, an
attacker could cause the plugin to crash or possibly execute arbitrary
code as the user invoking the program.

This problem was initially discovered by Arthur Gerkis and got assigned
CVE-2012-4540
. Fixes where applied in the 1.1, 1.2 and 1.3 branches but
not to the 1.4 branch.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"icedtea-6-plugin", ver:"1.4-3~deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedtea-7-plugin", ver:"1.4-3~deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedtea-netx", ver:"1.4-3~deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedtea-netx-common", ver:"1.4-3~deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedtea-plugin", ver:"1.4-3~deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"1.4-3~deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
