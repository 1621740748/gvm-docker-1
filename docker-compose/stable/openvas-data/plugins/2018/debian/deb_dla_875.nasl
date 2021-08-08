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
  script_oid("1.3.6.1.4.1.25623.1.0.890875");
  script_version("2021-06-18T02:00:26+0000");
  script_cve_id("CVE-2015-8876", "CVE-2016-7478", "CVE-2016-7479", "CVE-2017-7272");
  script_name("Debian LTS: Security Advisory for php5 (DLA-875-1)");
  script_tag(name:"last_modification", value:"2021-06-18 02:00:26 +0000 (Fri, 18 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-01-12 00:00:00 +0100 (Fri, 12 Jan 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-14 18:48:00 +0000 (Thu, 14 Feb 2019)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/03/msg00033.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"php5 on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
5.4.45-0+deb7u8.

We recommend that you upgrade your php5 packages.");

  script_tag(name:"summary", value:"Several issues have been discovered in PHP (recursive acronym for PHP:
Hypertext Preprocessor), a widely-used open source general-purpose
scripting language that is especially suited for web development and can
be embedded into HTML.

CVE-2016-7478:
Zend/zend_exceptions.c in PHP allows remote attackers to
cause a denial of service (infinite loop) via a crafted Exception
object in serialized data, a related issue to CVE-2015-8876.

CVE-2016-7479:
During the unserialization process, resizing the 'properties' hash
table of a serialized object may lead to use-after-free. A remote
attacker may exploit this bug to gain the ability of arbitrary code
execution. Even though the property table issue only affects PHP 7
this change also prevents a wide range of other __wakeup() based
attacks.

CVE-2017-7272:
The fsockopen() function will use the port number which is defined
in hostname instead of the port number passed to the second
parameter of the function. This misbehavior may introduce another
attack vector for an already known application vulnerability (e.g.
Server Side Request Forgery).");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5filter", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libphp5-embed", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-pear", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-common", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-curl", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-dbg", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-dev", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-enchant", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-fpm", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-gd", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-gmp", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-imap", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-interbase", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-intl", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-ldap", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-mcrypt", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-mysql", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-mysqlnd", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-odbc", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-pspell", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-recode", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-snmp", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-sybase", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-tidy", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-xsl", ver:"5.4.45-0+deb7u8", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
