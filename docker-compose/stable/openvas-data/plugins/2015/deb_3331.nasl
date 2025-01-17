# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 3331-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH http://greenbone.net
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703331");
  script_version("2020-04-21T10:50:58+0000");
  script_cve_id("CVE-2015-3184", "CVE-2015-3187");
  script_name("Debian Security Advisory DSA 3331-1 (subversion - security update)");
  script_tag(name:"last_modification", value:"2020-04-21 10:50:58 +0000 (Tue, 21 Apr 2020)");
  script_tag(name:"creation_date", value:"2015-08-10 00:00:00 +0200 (Mon, 10 Aug 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3331.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");
  script_tag(name:"affected", value:"subversion on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy), this problem has been fixed
in version 1.6.17dfsg-4+deb7u10.

For the stable distribution (jessie), these problems have been fixed in
version 1.8.10-6+deb8u1.

For the testing distribution (stretch), these problems will be fixed in
version 1.9.0-1.

For the unstable distribution (sid), these problems have been fixed in
version 1.9.0-1.

We recommend that you upgrade your subversion packages.");
  script_tag(name:"summary", value:"Several security issues have been found in the server components of the
version control system subversion.

CVE-2015-3184
Subversion's mod_authz_svn does not properly restrict anonymous
access in some mixed anonymous/authenticated environments when
using Apache httpd 2.4. The result is that anonymous access may
be possible to files for which only authenticated access should
be possible. This issue does not affect the oldstable distribution
(wheezy) because it only contains Apache httpd 2.2.

CVE-2015-3187
Subversion servers, both httpd and svnserve, will reveal some
paths that should be hidden by path-based authz. When a node is
copied from an unreadable location to a readable location the
unreadable path may be revealed. This vulnerability only reveals
the path, it does not reveal the contents of the path.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.6.17dfsg-4+deb7u10", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn-dev", ver:"1.6.17dfsg-4+deb7u10", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn-doc", ver:"1.6.17dfsg-4+deb7u10", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn-java", ver:"1.6.17dfsg-4+deb7u10", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn-perl", ver:"1.6.17dfsg-4+deb7u10", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn-ruby", ver:"1.6.17dfsg-4+deb7u10", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn-ruby1.8", ver:"1.6.17dfsg-4+deb7u10", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn1", ver:"1.6.17dfsg-4+deb7u10", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-subversion", ver:"1.6.17dfsg-4+deb7u10", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"subversion", ver:"1.6.17dfsg-4+deb7u10", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"subversion-tools", ver:"1.6.17dfsg-4+deb7u10", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-svn", ver:"1.8.10-6+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.8.10-6+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn-dev", ver:"1.8.10-6+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn-doc", ver:"1.8.10-6+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn-java", ver:"1.8.10-6+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn-perl", ver:"1.8.10-6+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn-ruby1.8", ver:"1.8.10-6+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn1", ver:"1.8.10-6+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-subversion", ver:"1.8.10-6+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby-svn", ver:"1.8.10-6+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"subversion", ver:"1.8.10-6+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"subversion-dbg", ver:"1.8.10-6+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"subversion-tools", ver:"1.8.10-6+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
