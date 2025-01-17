###############################################################################
# OpenVAS Vulnerability Test
#
# Auto-generated from advisory DSA 4349-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704349");
  script_version("2021-06-22T02:00:27+0000");
  script_cve_id("CVE-2017-11613", "CVE-2017-17095", "CVE-2018-10963", "CVE-2018-15209", "CVE-2018-16335",
                "CVE-2018-17101", "CVE-2018-18557", "CVE-2018-5784", "CVE-2018-7456", "CVE-2018-8905");
  script_name("Debian Security Advisory DSA 4349-1 (tiff - security update)");
  script_tag(name:"last_modification", value:"2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-11-30 00:00:00 +0100 (Fri, 30 Nov 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-01 11:29:00 +0000 (Sat, 01 Dec 2018)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4349.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"tiff on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), these problems have been fixed in
version 4.0.8-2+deb9u4.

We recommend that you upgrade your tiff packages.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/tiff");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been discovered in the libtiff library and
the included tools, which may result in denial of service or the
execution of arbitrary code if malformed image files are processed.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libtiff-doc", ver:"4.0.8-2+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtiff-opengl", ver:"4.0.8-2+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtiff-tools", ver:"4.0.8-2+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtiff5", ver:"4.0.8-2+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtiff5-dev", ver:"4.0.8-2+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtiffxx5", ver:"4.0.8-2+deb9u4", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}