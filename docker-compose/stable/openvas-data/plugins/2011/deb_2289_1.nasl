# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 2289-1 (typo3-src)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.70225");
  script_version("2021-05-19T13:10:04+0000");
  script_tag(name:"last_modification", value:"2021-05-19 13:10:04 +0000 (Wed, 19 May 2021)");
  script_tag(name:"creation_date", value:"2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-08 16:38:00 +0000 (Fri, 08 Nov 2019)");
  script_name("Debian Security Advisory DSA 2289-1 (typo3-src)");
  script_cve_id("CVE-2011-4626", "CVE-2011-4627", "CVE-2011-4628", "CVE-2011-4629", "CVE-2011-4630",
               "CVE-2011-4631", "CVE-2011-4632", "CVE-2011-4900", "CVE-2011-4901", "CVE-2011-4902",
               "CVE-2011-4903", "CVE-2011-4904");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6|7)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202289-1");
  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the TYPO3 web
content management framework: cross-site scripting, information
disclosure, authentication delay bypass, and arbitrary file deletion.

For the oldstable distribution (lenny), these problems have been fixed in
version 4.2.5-1+lenny8.

For the stable distribution (squeeze), these problems have been fixed in
version 4.3.9+dfsg1-1+squeeze1.

For the testing distribution (wheezy) and the unstable distribution
(sid), these problems have been fixed in version 4.5.4+dfsg1-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your typo3-src packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to typo3-src
announced via advisory DSA 2289-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"typo3", ver:"4.2.5-1+lenny8", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-src-4.2", ver:"4.2.5-1+lenny8", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3", ver:"4.3.9+dfsg1-1+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-database", ver:"4.3.9+dfsg1-1+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-src-4.3", ver:"4.3.9+dfsg1-1+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3", ver:"4.5.4+dfsg1-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-database", ver:"4.5.4+dfsg1-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-dummy", ver:"4.5.4+dfsg1-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-src-4.5", ver:"4.5.4+dfsg1-1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}