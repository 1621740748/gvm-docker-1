# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 2937-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.702937");
  script_version("2019-12-20T08:10:23+0000");
  script_cve_id("CVE-2014-0240", "CVE-2014-0242");
  script_name("Debian Security Advisory DSA 2937-1 (mod-wsgi - security update)");
  script_tag(name:"last_modification", value:"2019-12-20 08:10:23 +0000 (Fri, 20 Dec 2019)");
  script_tag(name:"creation_date", value:"2014-05-27 00:00:00 +0200 (Tue, 27 May 2014)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2937.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"mod-wsgi on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (squeeze), these problems have been fixed in
version 3.3-2+deb6u1.

For the stable distribution (wheezy), these problems have been fixed in
version 3.3-4+deb7u1.

For the testing distribution (jessie), these problems have been fixed in
version 3.5-1.

For the unstable distribution (sid), these problems have been fixed in
version 3.5-1.

We recommend that you upgrade your mod-wsgi packages.");
  script_tag(name:"summary", value:"Two security issues have been found in the Python WSGI adapter module
for Apache:

CVE-2014-0240
Robert Kisteleki discovered a potential privilege escalation in
daemon mode. This is not exploitable with the kernel used in Debian
7.0/wheezy.

CVE-2014-0242
Buck Golemon discovered that incorrect memory handling could lead to
information disclosure when processing Content-Type headers.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libapache2-mod-wsgi", ver:"3.3-2+deb6u1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-wsgi-py3", ver:"3.3-2+deb6u1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-wsgi", ver:"3.3-4+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-wsgi-py3", ver:"3.3-4+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}