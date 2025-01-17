# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 2733-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.702733");
  script_version("2021-07-05T02:00:48+0000");
  script_cve_id("CVE-2013-2625", "CVE-2012-4751", "CVE-2013-4088", "CVE-2013-4717");
  script_name("Debian Security Advisory DSA 2733-1 (otrs2 - SQL injection)");
  script_tag(name:"last_modification", value:"2021-07-05 02:00:48 +0000 (Mon, 05 Jul 2021)");
  script_tag(name:"creation_date", value:"2013-08-02 00:00:00 +0200 (Fri, 02 Aug 2013)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2733.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"otrs2 on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (squeeze), this problem has been fixed in
version 2.4.9+dfsg1-3+squeeze4. This update also provides fixes for
CVE-2012-4751, CVE-2013-2625 and CVE-2013-4088
, which were all fixed for
stable already.

For the stable distribution (wheezy), this problem has been fixed in
version 3.1.7+dfsg1-8+deb7u3.

For the testing distribution (jessie), this problem has been fixed in
version 3.2.9-1.

For the unstable distribution (sid), this problem has been fixed in
version 3.2.9-1.

We recommend that you upgrade your otrs2 packages.");
  script_tag(name:"summary", value:"It was discovered that otrs2, the Open Ticket Request System, does not
properly sanitise user-supplied data that is used on SQL queries. An
attacker with a valid agent login could exploit this issue to craft SQL
queries by injecting arbitrary SQL code through manipulated URLs.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"otrs2", ver:"2.4.9+dfsg1-3+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"otrs", ver:"3.1.7+dfsg1-8+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"otrs2", ver:"3.1.7+dfsg1-8+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
