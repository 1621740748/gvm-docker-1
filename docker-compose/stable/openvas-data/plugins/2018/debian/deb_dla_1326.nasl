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
  script_oid("1.3.6.1.4.1.25623.1.0.891326");
  script_version("2021-06-17T11:00:26+0000");
  script_cve_id("CVE-2018-7584");
  script_name("Debian LTS: Security Advisory for php5 (DLA-1326-1)");
  script_tag(name:"last_modification", value:"2021-06-17 11:00:26 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-04-02 00:00:00 +0200 (Mon, 02 Apr 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-19 11:15:00 +0000 (Mon, 19 Aug 2019)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/03/msg00030.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"php5 on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
5.4.45-0+deb7u13.

We recommend that you upgrade your php5 packages.");

  script_tag(name:"summary", value:"Wei Lei and Liu Yang of Nanyang Technological University discovered a
stack-based buffer overflow in PHP5 when parsing a malformed HTTP
response which can be exploited to cause a denial-of-service.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5filter", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libphp5-embed", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-pear", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-common", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-curl", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-dbg", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-dev", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-enchant", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-fpm", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-gd", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-gmp", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-imap", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-interbase", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-intl", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-ldap", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-mcrypt", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-mysql", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-mysqlnd", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-odbc", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-pspell", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-recode", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-snmp", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-sybase", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-tidy", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-xsl", ver:"5.4.45-0+deb7u13", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
