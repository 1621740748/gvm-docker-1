###############################################################################
# OpenVAS Vulnerability Test
#
# Auto-generated from advisory DSA 4089-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.704089");
  script_version("2021-06-17T11:57:04+0000");
  script_cve_id("CVE-2017-3145");
  script_name("Debian Security Advisory DSA 4089-1 (bind9 - security update)");
  script_tag(name:"last_modification", value:"2021-06-17 11:57:04 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-01-16 00:00:00 +0100 (Tue, 16 Jan 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:27:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4089.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|8)");
  script_tag(name:"affected", value:"bind9 on Debian Linux");

  script_tag(name:"solution", value:"For the oldstable distribution (jessie), this problem has been fixed
in version 1:9.9.5.dfsg-9+deb8u15.

For the stable distribution (stretch), this problem has been fixed in
version 1:9.10.3.dfsg.P4-12.3+deb9u4.

We recommend that you upgrade your bind9 packages.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/bind9");
  script_tag(name:"summary", value:"Jayachandran Palanisamy of Cygate AB reported that BIND, a DNS server
implementation, was improperly sequencing cleanup operations, leading in
some cases to a use-after-free error, triggering an assertion failure
and crash in named.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.10.3.dfsg.P4-12.3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bind9-doc", ver:"1:9.10.3.dfsg.P4-12.3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bind9-host", ver:"1:9.10.3.dfsg.P4-12.3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bind9utils", ver:"1:9.10.3.dfsg.P4-12.3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dnsutils", ver:"1:9.10.3.dfsg.P4-12.3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"host", ver:"1:9.10.3.dfsg.P4-12.3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbind-dev", ver:"1:9.10.3.dfsg.P4-12.3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbind-export-dev", ver:"1:9.10.3.dfsg.P4-12.3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbind9-140", ver:"1:9.10.3.dfsg.P4-12.3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libdns-export162", ver:"1:9.10.3.dfsg.P4-12.3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libdns162", ver:"1:9.10.3.dfsg.P4-12.3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libirs-export141", ver:"1:9.10.3.dfsg.P4-12.3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libirs141", ver:"1:9.10.3.dfsg.P4-12.3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisc-export160", ver:"1:9.10.3.dfsg.P4-12.3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisc160", ver:"1:9.10.3.dfsg.P4-12.3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisccc-export140", ver:"1:9.10.3.dfsg.P4-12.3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisccc140", ver:"1:9.10.3.dfsg.P4-12.3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisccfg-export140", ver:"1:9.10.3.dfsg.P4-12.3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisccfg140", ver:"1:9.10.3.dfsg.P4-12.3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblwres141", ver:"1:9.10.3.dfsg.P4-12.3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lwresd", ver:"1:9.10.3.dfsg.P4-12.3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.9.5.dfsg-9+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bind9-doc", ver:"1:9.9.5.dfsg-9+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bind9-host", ver:"1:9.9.5.dfsg-9+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bind9utils", ver:"1:9.9.5.dfsg-9+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dnsutils", ver:"1:9.9.5.dfsg-9+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"host", ver:"1:9.9.5.dfsg-9+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbind-dev", ver:"1:9.9.5.dfsg-9+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbind-export-dev", ver:"1:9.9.5.dfsg-9+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbind9-90", ver:"1:9.9.5.dfsg-9+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libdns-export100", ver:"1:9.9.5.dfsg-9+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libdns100", ver:"1:9.9.5.dfsg-9+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libirs-export91", ver:"1:9.9.5.dfsg-9+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisc-export95", ver:"1:9.9.5.dfsg-9+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisc95", ver:"1:9.9.5.dfsg-9+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisccc90", ver:"1:9.9.5.dfsg-9+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisccfg-export90", ver:"1:9.9.5.dfsg-9+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisccfg90", ver:"1:9.9.5.dfsg-9+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblwres90", ver:"1:9.9.5.dfsg-9+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lwresd", ver:"1:9.9.5.dfsg-9+deb8u15", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}