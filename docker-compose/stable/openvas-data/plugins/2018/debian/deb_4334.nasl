###############################################################################
# OpenVAS Vulnerability Test
#
# Auto-generated from advisory DSA 4334-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704334");
  script_version("2021-06-21T03:34:17+0000");
  script_cve_id("CVE-2017-17866", "CVE-2018-1000037", "CVE-2018-1000040", "CVE-2018-5686", "CVE-2018-6187",
                "CVE-2018-6192");
  script_name("Debian Security Advisory DSA 4334-1 (mupdf - security update)");
  script_tag(name:"last_modification", value:"2021-06-21 03:34:17 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-11-04 00:00:00 +0100 (Sun, 04 Nov 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-11 13:32:00 +0000 (Mon, 11 Mar 2019)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4334.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"mupdf on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), these problems have been fixed in
version 1.9a+ds1-4+deb9u4.

We recommend that you upgrade your mupdf packages.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/mupdf");
  script_tag(name:"summary", value:"Multiple vulnerabilities were discovered in MuPDF, a PDF, XPS, and e-book
viewer which could result in denial of service or the execution of
arbitrary code if malformed documents are opened.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libmupdf-dev", ver:"1.9a+ds1-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mupdf", ver:"1.9a+ds1-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mupdf-tools", ver:"1.9a+ds1-4+deb9u4", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}