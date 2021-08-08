###############################################################################
# OpenVAS Vulnerability Test
#
# Auto-generated from advisory DSA 4231-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704231");
  script_version("2021-06-21T03:34:17+0000");
  script_cve_id("CVE-2018-0495");
  script_name("Debian Security Advisory DSA 4231-1 (libgcrypt20 - security update)");
  script_tag(name:"last_modification", value:"2021-06-21 03:34:17 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-06-17 00:00:00 +0200 (Sun, 17 Jun 2018)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4231.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"libgcrypt20 on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), this problem has been fixed in
version 1.7.6-2+deb9u3.

We recommend that you upgrade your libgcrypt20 packages.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libgcrypt20");
  script_tag(name:"summary", value:"It was discovered that Libgcrypt is prone to a local side-channel attack
allowing recovery of ECDSA private keys.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libgcrypt-mingw-w64-dev", ver:"1.7.6-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgcrypt20", ver:"1.7.6-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgcrypt20-dev", ver:"1.7.6-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgcrypt20-doc", ver:"1.7.6-2+deb9u3", rls:"DEB9"))) {
  report += res;
}

# nb: This is using a different version scheme, take care of this when overwriting this LSC...
if(!isnull(res = isdpkgvuln(pkg:"libgcrypt11-dev", ver:"1.5.4-3+really1.7.6-2+deb9u3", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
