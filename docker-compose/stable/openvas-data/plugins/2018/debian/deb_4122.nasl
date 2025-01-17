###############################################################################
# OpenVAS Vulnerability Test
#
# Auto-generated from advisory DSA 4122-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704122");
  script_version("2021-06-16T13:21:12+0000");
  script_cve_id("CVE-2018-1000024", "CVE-2018-1000027");
  script_name("Debian Security Advisory DSA 4122-1 (squid3 - security update)");
  script_tag(name:"last_modification", value:"2021-06-16 13:21:12 +0000 (Wed, 16 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-02-23 00:00:00 +0100 (Fri, 23 Feb 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4122.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|8)");
  script_tag(name:"affected", value:"squid3 on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), these problems have been fixed
in version 3.4.8-6+deb8u5.

For the stable distribution (stretch), these problems have been fixed in
version 3.5.23-5+deb9u1.

We recommend that you upgrade your squid3 packages.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/squid3");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in Squid3, a fully featured
web proxy cache. The Common Vulnerabilities and Exposures project
identifies the following issues:

CVE-2018-1000024
Louis Dion-Marcil discovered that Squid does not properly handle
processing of certain ESI responses. A remote server delivering
certain ESI response syntax can take advantage of this flaw to cause
a denial of service for all clients accessing the Squid service.
This problem is limited to the Squid custom ESI parser.

CVE-2018-1000027
Louis Dion-Marcil discovered that Squid is prone to a denial of
service vulnerability when processing ESI responses or downloading
intermediate CA certificates. A remote attacker can take advantage
of this flaw to cause a denial of service for all clients accessing
the Squid service.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"squid", ver:"3.5.23-5+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid-cgi", ver:"3.5.23-5+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid-common", ver:"3.5.23-5+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid-dbg", ver:"3.5.23-5+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid-purge", ver:"3.5.23-5+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid3", ver:"3.5.23-5+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squidclient", ver:"3.5.23-5+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid-cgi", ver:"3.4.8-6+deb8u5", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid-purge", ver:"3.4.8-6+deb8u5", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid3", ver:"3.4.8-6+deb8u5", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid3-common", ver:"3.4.8-6+deb8u5", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid3-dbg", ver:"3.4.8-6+deb8u5", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squidclient", ver:"3.4.8-6+deb8u5", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}