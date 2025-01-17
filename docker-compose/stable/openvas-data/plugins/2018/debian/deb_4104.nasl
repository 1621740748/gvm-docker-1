###############################################################################
# OpenVAS Vulnerability Test
#
# Auto-generated from advisory DSA 4104-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704104");
  script_version("2021-06-21T03:34:17+0000");
  script_cve_id("CVE-2017-17969");
  script_name("Debian Security Advisory DSA 4104-1 (p7zip - security update)");
  script_tag(name:"last_modification", value:"2021-06-21 03:34:17 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-02-04 00:00:00 +0100 (Sun, 04 Feb 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-21 20:29:00 +0000 (Thu, 21 Mar 2019)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4104.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");
  script_tag(name:"affected", value:"p7zip on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), this problem has been fixed
in version 9.20.1~dfsg.1-4.1+deb8u3.

For the stable distribution (stretch), this problem has been fixed in
version 16.02+dfsg-3+deb9u1.

We recommend that you upgrade your p7zip packages.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/p7zip");
  script_tag(name:"summary", value:"'landave' discovered a heap-based buffer overflow vulnerability in the
NCompress::NShrink::CDecoder::CodeReal method in p7zip, a 7zr file
archiver with high compression ratio. A remote attacker can take
advantage of this flaw to cause a denial-of-service or, potentially the
execution of arbitrary code with the privileges of the user running
p7zip, if a specially crafted shrunk ZIP archive is processed.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"p7zip", ver:"9.20.1~dfsg.1-4.1+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"p7zip-full", ver:"9.20.1~dfsg.1-4.1+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"p7zip", ver:"16.02+dfsg-3+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"p7zip-full", ver:"16.02+dfsg-3+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
