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
  script_oid("1.3.6.1.4.1.25623.1.0.891336");
  script_version("2021-06-16T11:00:23+0000");
  script_cve_id("CVE-2018-1000075", "CVE-2018-1000076", "CVE-2018-1000077", "CVE-2018-1000078");
  script_name("Debian LTS: Security Advisory for rubygems (DLA-1336-1)");
  script_tag(name:"last_modification", value:"2021-06-16 11:00:23 +0000 (Wed, 16 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-04-02 00:00:00 +0200 (Mon, 02 Apr 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-20 13:29:00 +0000 (Mon, 20 May 2019)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/04/msg00000.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"rubygems on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
1.8.24-1+deb7u2.

We recommend that you upgrade your rubygems packages.");

  script_tag(name:"summary", value:"Multiple vulnerabilities were found in rubygems, a package management framework
for Ruby.

CVE-2018-1000075

A negative size vulnerability in ruby gem package tar header that could
cause an infinite loop.

CVE-2018-1000076

Ruby gems package improperly verifies cryptographic signatures. A mis-signed
gem could be installed if the tarball contains multiple gem signatures.

CVE-2018-1000077

An improper input validation vulnerability in ruby gems specification
homepage attribute could allow malicious gem to set an invalid homepage
URL.

CVE-2018-1000078

Cross Site Scripting (XSS) vulnerability in gem server display of homepage
attribute");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"rubygems", ver:"1.8.24-1+deb7u2", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"rubygems-doc", ver:"1.8.24-1+deb7u2", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"rubygems1.8", ver:"1.8.24-1+deb7u2", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
