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
  script_oid("1.3.6.1.4.1.25623.1.0.891229");
  script_version("2021-06-21T11:00:26+0000");
  script_cve_id("CVE-2017-1000445", "CVE-2017-1000476");
  script_name("Debian LTS: Security Advisory for imagemagick (DLA-1229-1)");
  script_tag(name:"last_modification", value:"2021-06-21 11:00:26 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-01-09 00:00:00 +0100 (Tue, 09 Jan 2018)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 00:15:00 +0000 (Tue, 08 Sep 2020)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/01/msg00002.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"imagemagick on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', this issue has been fixed in imagemagick version
8:6.7.7.10-5+deb7u20.

We recommend that you upgrade your imagemagick packages.");

  script_tag(name:"summary", value:"It was discovered that there were two vulnerabilities in the imagemagick
image manipulation program:

CVE-2017-1000445: A null pointer dereference in the MagickCore
component which could lead to denial of service.

CVE-2017-1000476: A potential denial of service attack via CPU
exhaustion.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.7.7.10-5+deb7u20", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"imagemagick-common", ver:"8:6.7.7.10-5+deb7u20", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"imagemagick-dbg", ver:"8:6.7.7.10-5+deb7u20", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"imagemagick-doc", ver:"8:6.7.7.10-5+deb7u20", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libmagick++-dev", ver:"8:6.7.7.10-5+deb7u20", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libmagick++5", ver:"8:6.7.7.10-5+deb7u20", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-dev", ver:"8:6.7.7.10-5+deb7u20", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libmagickcore5", ver:"8:6.7.7.10-5+deb7u20", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libmagickcore5-extra", ver:"8:6.7.7.10-5+deb7u20", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-dev", ver:"8:6.7.7.10-5+deb7u20", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libmagickwand5", ver:"8:6.7.7.10-5+deb7u20", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"perlmagick", ver:"8:6.7.7.10-5+deb7u20", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
