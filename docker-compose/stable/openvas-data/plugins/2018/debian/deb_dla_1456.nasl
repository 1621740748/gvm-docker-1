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
  script_oid("1.3.6.1.4.1.25623.1.0.891456");
  script_version("2021-06-15T11:41:24+0000");
  script_cve_id("CVE-2016-5239", "CVE-2017-11102", "CVE-2017-11140", "CVE-2017-11403", "CVE-2017-11637",
                "CVE-2017-11638", "CVE-2017-11641", "CVE-2017-11642", "CVE-2017-12935", "CVE-2017-12936",
                "CVE-2017-13737", "CVE-2017-13775", "CVE-2017-13776", "CVE-2017-13777", "CVE-2017-14504",
                "CVE-2017-14994", "CVE-2017-14997", "CVE-2017-15277", "CVE-2017-15930", "CVE-2017-16352",
                "CVE-2017-16545", "CVE-2017-16547", "CVE-2017-18219", "CVE-2017-18220", "CVE-2017-18229",
                "CVE-2017-18230", "CVE-2017-18231", "CVE-2017-6335", "CVE-2017-9098", "CVE-2018-5685",
                "CVE-2018-6799", "CVE-2018-9018");
  script_name("Debian LTS: Security Advisory for graphicsmagick (DLA-1456-1)");
  script_tag(name:"last_modification", value:"2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-08-03 00:00:00 +0200 (Fri, 03 Aug 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-04 01:29:00 +0000 (Sat, 04 Aug 2018)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/08/msg00002.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_tag(name:"affected", value:"graphicsmagick on Debian Linux");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1.3.20-3+deb8u4.

We recommend that you upgrade your graphicsmagick packages.");

  script_tag(name:"summary", value:"Various vulnerabilities were discovered in graphicsmagick, a collection
of image processing tools and associated libraries, resulting in denial
of service, information disclosure, and a variety of buffer overflows
and overreads.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick", ver:"1.3.20-3+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick-dbg", ver:"1.3.20-3+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick-imagemagick-compat", ver:"1.3.20-3+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick-libmagick-dev-compat", ver:"1.3.20-3+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgraphics-magick-perl", ver:"1.3.20-3+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick++1-dev", ver:"1.3.20-3+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick++3", ver:"1.3.20-3+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick1-dev", ver:"1.3.20-3+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick3", ver:"1.3.20-3+deb8u4", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
