# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 2660-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.702660");
  script_version("2020-10-05T06:02:24+0000");
  script_cve_id("CVE-2013-1944");
  script_name("Debian Security Advisory DSA 2660-1 (curl - exposure of sensitive information)");
  script_tag(name:"last_modification", value:"2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)");
  script_tag(name:"creation_date", value:"2013-04-20 00:00:00 +0200 (Sat, 20 Apr 2013)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2660.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"curl on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (squeeze), this problem has been fixed in
version 7.21.0-2.1+squeeze3.

For the testing distribution (wheezy), this problem has been fixed in
version 7.26.0-1+wheezy2.

For the unstable distribution (sid), this problem has been fixed in
version 7.29.0-2.1.

We recommend that you upgrade your curl packages.");
  script_tag(name:"summary", value:"Yamada Yasuharu discovered that cURL, an URL transfer library, is
vulnerable to expose potentially sensitive information when doing
requests across domains with matching tails. Due to a bug in the
tailmatch function when matching domain names, it was possible that
cookies set for a domain ample.com could accidentally also be sent
by libcurl when communicating with example.com
.

Both curl the command line tool and applications using the libcurl
library are vulnerable.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"curl", ver:"7.21.0-2.1+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3", ver:"7.21.0-2.1+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-dbg", ver:"7.21.0-2.1+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.21.0-2.1+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl4-gnutls-dev", ver:"7.21.0-2.1+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl4-openssl-dev", ver:"7.21.0-2.1+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"curl", ver:"7.26.0-1+wheezy2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3", ver:"7.26.0-1+wheezy2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-dbg", ver:"7.26.0-1+wheezy2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.26.0-1+wheezy2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-nss", ver:"7.26.0-1+wheezy2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl4-gnutls-dev", ver:"7.26.0-1+wheezy2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl4-nss-dev", ver:"7.26.0-1+wheezy2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl4-openssl-dev", ver:"7.26.0-1+wheezy2", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
