# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 2631-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.702631");
  script_version("2020-10-05T06:02:24+0000");
  script_cve_id("CVE-2013-0189", "CVE-2012-5643");
  script_name("Debian Security Advisory DSA 2631-1 (squid3 - denial of service)");
  script_tag(name:"last_modification", value:"2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)");
  script_tag(name:"creation_date", value:"2013-02-24 00:00:00 +0100 (Sun, 24 Feb 2013)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2631.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"squid3 on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (squeeze), these problems have been fixed in
version 3.1.6-1.2+squeeze3.

For the testing distribution (wheezy), these problems have been fixed in
version 3.1.20-2.1.

For the unstable distribution (sid), these problems have been fixed in
version 3.1.20-2.1.

We recommend that you upgrade your squid3 packages.");
  script_tag(name:"summary", value:"Squid3, a fully featured Web proxy cache, is prone to a denial of
service attack due to memory consumption caused by memory leaks in
cachemgr.cgi:

CVE-2012-5643
squid's cachemgr.cgi was vulnerable to excessive resource use.
A remote attacker could exploit this flaw to perform a denial of
service attack on the server and other hosted services.

CVE-2013-0189The original patch for CVE-2012-5643

was incomplete. A remote attacker still could exploit this flaw
to perform a denial of service attack.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"squid-cgi", ver:"3.1.6-1.2+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squid3", ver:"3.1.6-1.2+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squid3-common", ver:"3.1.6-1.2+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squid3-dbg", ver:"3.1.6-1.2+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squidclient", ver:"3.1.6-1.2+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squid-cgi", ver:"3.1.20-2.1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squid3", ver:"3.1.20-2.1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squid3-common", ver:"3.1.20-2.1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squid3-dbg", ver:"3.1.20-2.1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squidclient", ver:"3.1.20-2.1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
