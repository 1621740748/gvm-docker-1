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
  script_oid("1.3.6.1.4.1.25623.1.0.891397");
  script_version("2021-06-15T11:41:24+0000");
  script_cve_id("CVE-2018-10545", "CVE-2018-10546", "CVE-2018-10547", "CVE-2018-10548", "CVE-2018-10549",
                "CVE-2018-5712", "CVE-2018-7584");
  script_name("Debian LTS: Security Advisory for php5 (DLA-1397-1)");
  script_tag(name:"last_modification", value:"2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-07-10 00:00:00 +0200 (Tue, 10 Jul 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-19 11:15:00 +0000 (Mon, 19 Aug 2019)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/06/msg00005.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_tag(name:"affected", value:"php5 on Debian Linux");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
5.6.36+dfsg-0+deb8u1.

We recommend that you upgrade your php5 packages.");

  script_tag(name:"summary", value:"Several vulnerabilities were found in PHP, a widely-used open source
general purpose scripting language:

CVE-2018-7584

A stack-buffer-overflow while parsing HTTP response results in copying a
large string and possible memory corruption and/or denial of service

CVE-2018-10545

Dumpable FPM child processes allow bypassing opcache access controls
resulting in potential information disclosure where one user can obtain
information about another user's running PHP applications

CVE-2018-10546

An invalid sequence of bytes can trigger an infinite loop in the stream
filter convert.iconv

CVE-2018-10547

A previous fix for CVE-2018-5712 may not be complete, resulting in an
additional vulnerability in the form of a reflected XSS in the PHAR 403
and 404 error pages

CVE-2018-10548

A malicious remote LDAP server can send a crafted response that will
cause a denial of service (NULL pointer dereference resulting in an
application crash)

CVE-2018-10549

A crafted JPEG file can case an out-of-bounds read and heap buffer
overflow");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5filter", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libphp5-embed", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-pear", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-common", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-curl", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-dbg", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-dev", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-enchant", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-fpm", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-gd", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-gmp", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-imap", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-interbase", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-intl", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-ldap", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-mcrypt", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-mysql", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-mysqlnd", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-odbc", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-phpdbg", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-pspell", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-readline", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-recode", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-snmp", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-sybase", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-tidy", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-xsl", ver:"5.6.36+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
