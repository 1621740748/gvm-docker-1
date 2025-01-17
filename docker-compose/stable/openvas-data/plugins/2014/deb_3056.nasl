# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 3056-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703056");
  script_version("2020-11-19T10:53:01+0000");
  script_cve_id("CVE-2014-3467", "CVE-2014-3468", "CVE-2014-3469");
  script_name("Debian Security Advisory DSA 3056-1 (libtasn1-3 - security update)");
  script_tag(name:"last_modification", value:"2020-11-19 10:53:01 +0000 (Thu, 19 Nov 2020)");
  script_tag(name:"creation_date", value:"2014-10-26 00:00:00 +0200 (Sun, 26 Oct 2014)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-3056.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"libtasn1-3 on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), these problems have been fixed in
version 2.13-2+deb7u1.

We recommend that you upgrade your libtasn1-3 packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered in libtasn1-3, a library that
manages ASN1 (Abstract Syntax Notation One) structures. An attacker
could use those to cause a denial-of-service via out-of-bounds access
or NULL pointer dereference.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libtasn1-3", ver:"2.13-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtasn1-3-bin", ver:"2.13-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtasn1-3-dbg", ver:"2.13-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtasn1-3-dev", ver:"2.13-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}