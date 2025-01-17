# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 3638-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703638");
  script_version("2020-05-14T10:14:42+0000");
  script_cve_id("CVE-2016-5419", "CVE-2016-5420", "CVE-2016-5421");
  script_name("Debian Security Advisory DSA 3638-1 (curl - security update)");
  script_tag(name:"last_modification", value:"2020-05-14 10:14:42 +0000 (Thu, 14 May 2020)");
  script_tag(name:"creation_date", value:"2016-08-03 00:00:00 +0200 (Wed, 03 Aug 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3638.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"curl on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie),
these problems have been fixed in version 7.38.0-4+deb8u4.

For the unstable distribution (sid), these problems have been fixed in
version 7.50.1-1.

We recommend that you upgrade your curl packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered
in cURL, an URL transfer library:

CVE-2016-5419
Bru Rom discovered that libcurl would attempt to resume a TLS session
even if the client certificate had changed.

CVE-2016-5420
It was discovered that libcurl did not consider client certificates
when reusing TLS connections.

CVE-2016-5421
Marcelo Echeverria and Fernando Munoz discovered that libcurl was
vulnerable to a use-after-free flaw.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"curl", ver:"7.38.0-4+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3:amd64", ver:"7.38.0-4+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3:i386", ver:"7.38.0-4+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-dbg:amd64", ver:"7.38.0-4+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-dbg:i386", ver:"7.38.0-4+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-gnutls:amd64", ver:"7.38.0-4+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-gnutls:i386", ver:"7.38.0-4+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-nss:amd64", ver:"7.38.0-4+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-nss:i386", ver:"7.38.0-4+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl4-doc", ver:"7.38.0-4+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl4-gnutls-dev:amd64", ver:"7.38.0-4+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl4-gnutls-dev:i386", ver:"7.38.0-4+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl4-nss-dev", ver:"7.38.0-4+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl4-openssl-dev", ver:"7.38.0-4+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
