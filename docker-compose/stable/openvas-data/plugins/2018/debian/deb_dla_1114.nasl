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
  script_oid("1.3.6.1.4.1.25623.1.0.891114");
  script_version("2021-06-17T02:00:27+0000");
  script_cve_id("CVE-2017-0898", "CVE-2017-0899", "CVE-2017-0900", "CVE-2017-0901", "CVE-2017-10784", "CVE-2017-14033", "CVE-2017-14064");
  script_name("Debian LTS: Security Advisory for ruby1.9.1 (DLA-1114-1)");
  script_tag(name:"last_modification", value:"2021-06-17 02:00:27 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-31 10:29:00 +0000 (Wed, 31 Oct 2018)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/09/msg00029.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"ruby1.9.1 on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
1.9.3.194-8.1+deb7u6.

We recommend that you upgrade your ruby1.9.1 packages.");

  script_tag(name:"summary", value:"Multiple vulnerabilities were discovered in the Ruby 1.9 interpreter.

CVE-2017-0898

Buffer underrun vulnerability in Kernel.sprintf

CVE-2017-0899

ANSI escape sequence vulnerability

CVE-2017-0900

DOS vulernerability in the query command

CVE-2017-0901

gem installer allows a malicious gem to overwrite arbitrary files

CVE-2017-10784

Escape sequence injection vulnerability in the Basic
authentication of WEBrick

CVE-2017-14033

Buffer underrun vulnerability in OpenSSL ASN1 decode

CVE-2017-14064

Heap exposure vulnerability in generating JSON");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libruby1.9.1", ver:"1.9.3.194-8.1+deb7u6", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libruby1.9.1-dbg", ver:"1.9.3.194-8.1+deb7u6", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtcltk-ruby1.9.1", ver:"1.9.3.194-8.1+deb7u6", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ri1.9.1", ver:"1.9.3.194-8.1+deb7u6", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1", ver:"1.9.3.194-8.1+deb7u6", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1-dev", ver:"1.9.3.194-8.1+deb7u6", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1-examples", ver:"1.9.3.194-8.1+deb7u6", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1-full", ver:"1.9.3.194-8.1+deb7u6", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.3", ver:"1.9.3.194-8.1+deb7u6", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
