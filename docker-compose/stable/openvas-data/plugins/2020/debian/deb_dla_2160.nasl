# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892160");
  script_version("2021-07-28T02:00:54+0000");
  script_cve_id("CVE-2020-7062", "CVE-2020-7063");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-07-28 02:00:54 +0000 (Wed, 28 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-08 12:15:00 +0000 (Wed, 08 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-03-27 04:00:11 +0000 (Fri, 27 Mar 2020)");
  script_name("Debian LTS: Security Advisory for php5 (DLA-2160-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/03/msg00034.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2160-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5'
  package(s) announced via the DLA-2160-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security issues have been identified and fixed in php5, a
server-side, HTML-embedded scripting language.

CVE-2020-7062 is about a possible null pointer dereference, which would
likely lead to a crash, during a failed upload with progress tracking.
CVE-2020-7063 is about wrong file permissions of files added to tar with
Phar::buildFromIterator when extracting them again.");

  script_tag(name:"affected", value:"'php5' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
5.6.40+dfsg-0+deb8u10.

We recommend that you upgrade your php5 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5filter", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libphp5-embed", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php-pear", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-common", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-curl", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-dbg", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-dev", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-enchant", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-fpm", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-gd", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-gmp", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-imap", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-interbase", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-intl", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-ldap", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-mcrypt", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-mysql", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-mysqlnd", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-odbc", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-phpdbg", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-pspell", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-readline", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-recode", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-snmp", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-sybase", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-tidy", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-xsl", ver:"5.6.40+dfsg-0+deb8u10", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
