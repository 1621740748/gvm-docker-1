# Copyright (C) 2018 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891093");
  script_version("2021-06-21T02:00:27+0000");
  script_cve_id("CVE-2017-11335", "CVE-2017-12944", "CVE-2017-13726", "CVE-2017-13727");
  script_name("Debian LTS: Security Advisory for tiff (DLA-1093-1)");
  script_tag(name:"last_modification", value:"2021-06-21 02:00:27 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-22 01:29:00 +0000 (Thu, 22 Mar 2018)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/09/msg00010.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"tiff on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
4.0.2-6+deb7u16.

We recommend that you upgrade your tiff packages.");

  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in the Tag Image File
Format (TIFF) library and its associated tools.

CVE-2017-11335

A heap based buffer overflow via a PlanarConfig=Contig image, which
causes an out-of-bounds write (related to the ZIPDecode function). A
crafted input may lead to a remote denial of service attack or an
arbitrary code execution attack.

CVE-2017-12944

A mishandling of memory allocation for short files allows attackers
to cause a denial of service (allocation failure and application
crash) during a tiff2pdf invocation.

CVE-2017-13726

A reachable assertion abort allows a crafted input to lead to a
remote denial of service attack.

CVE-2017-13727

A reachable assertion abort allows a crafted input to lead to a
remote denial of service attack.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libtiff-doc", ver:"4.0.2-6+deb7u16", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtiff-opengl", ver:"4.0.2-6+deb7u16", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtiff-tools", ver:"4.0.2-6+deb7u16", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtiff5", ver:"4.0.2-6+deb7u16", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtiff5-alt-dev", ver:"4.0.2-6+deb7u16", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtiff5-dev", ver:"4.0.2-6+deb7u16", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtiffxx5", ver:"4.0.2-6+deb7u16", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
