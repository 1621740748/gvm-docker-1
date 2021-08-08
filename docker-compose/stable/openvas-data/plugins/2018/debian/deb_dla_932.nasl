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
  script_oid("1.3.6.1.4.1.25623.1.0.890932");
  script_version("2021-06-16T11:00:23+0000");
  script_cve_id("CVE-2017-8291");
  script_name("Debian LTS: Security Advisory for ghostscript (DLA-932-1)");
  script_tag(name:"last_modification", value:"2021-06-16 11:00:23 +0000 (Wed, 16 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-01-25 00:00:00 +0100 (Thu, 25 Jan 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/05/msg00002.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"ghostscript on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
9.05~dfsg-6.3+deb7u6.

We recommend that you upgrade your ghostscript packages.");

  script_tag(name:"summary", value:"vulnerability was discovered in Ghostscript, the GPL PostScript/PDF
interpreter, which may lead to the execution of arbitrary code or denial
of service if a specially crafted Postscript file is processed.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"ghostscript", ver:"9.05~dfsg-6.3+deb7u6", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ghostscript-cups", ver:"9.05~dfsg-6.3+deb7u6", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ghostscript-dbg", ver:"9.05~dfsg-6.3+deb7u6", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ghostscript-doc", ver:"9.05~dfsg-6.3+deb7u6", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ghostscript-x", ver:"9.05~dfsg-6.3+deb7u6", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgs-dev", ver:"9.05~dfsg-6.3+deb7u6", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgs9", ver:"9.05~dfsg-6.3+deb7u6", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgs9-common", ver:"9.05~dfsg-6.3+deb7u6", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}