###############################################################################
# OpenVAS Vulnerability Test
#
# Auto-generated from advisory DSA 4232-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704232");
  script_version("2021-06-21T12:14:05+0000");
  script_cve_id("CVE-2018-3665");
  script_name("Debian Security Advisory DSA 4232-1 (xen - security update)");
  script_tag(name:"last_modification", value:"2021-06-21 12:14:05 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-06-20 00:00:00 +0200 (Wed, 20 Jun 2018)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-09 16:24:00 +0000 (Wed, 09 Jun 2021)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4232.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"xen on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), this problem has been fixed in
version 4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u8.

We recommend that you upgrade your xen packages.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/xen");
  script_tag(name:"summary", value:"This update provides mitigations for the lazy FPU vulnerability
affecting a range of Intel CPUs, which could result in leaking CPU
register states belonging to another vCPU previously scheduled on the
same CPU. For additional information please");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-267.html");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libxen-4.8", ver:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u8", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxen-dev", ver:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u8", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u8", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.8-amd64", ver:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u8", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.8-arm64", ver:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u8", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.8-armhf", ver:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u8", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-system-amd64", ver:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u8", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-system-arm64", ver:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u8", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-system-armhf", ver:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u8", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-utils-4.8", ver:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u8", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-utils-common", ver:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u8", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u8", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}