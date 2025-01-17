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
  script_oid("1.3.6.1.4.1.25623.1.0.891064");
  script_version("2021-06-21T11:00:26+0000");
  script_cve_id("CVE-2017-10978", "CVE-2017-10979", "CVE-2017-10980", "CVE-2017-10981", "CVE-2017-10982", "CVE-2017-10983");
  script_name("Debian LTS: Security Advisory for freeradius (DLA-1064-1)");
  script_tag(name:"last_modification", value:"2021-06-21 11:00:26 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/08/msg00016.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"freeradius on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
2.1.12+dfsg-1.2+deb7u2.

We recommend that you upgrade your freeradius packages.");

  script_tag(name:"summary", value:"Guido Vranken discovered that FreeRADIUS, an open source
implementation of RADIUS, the IETF protocol for AAA (Authorisation,
Authentication, and
Accounting), did not properly handle memory when processing packets.
This would allow a remote attacker to cause a denial-of-service by
application crash, or potentially execute arbitrary code.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"freeradius", ver:"2.1.12+dfsg-1.2+deb7u2", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"freeradius-common", ver:"2.1.12+dfsg-1.2+deb7u2", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"freeradius-dbg", ver:"2.1.12+dfsg-1.2+deb7u2", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"freeradius-dialupadmin", ver:"2.1.12+dfsg-1.2+deb7u2", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"freeradius-iodbc", ver:"2.1.12+dfsg-1.2+deb7u2", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"freeradius-krb5", ver:"2.1.12+dfsg-1.2+deb7u2", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"freeradius-ldap", ver:"2.1.12+dfsg-1.2+deb7u2", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"freeradius-mysql", ver:"2.1.12+dfsg-1.2+deb7u2", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"freeradius-postgresql", ver:"2.1.12+dfsg-1.2+deb7u2", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"freeradius-utils", ver:"2.1.12+dfsg-1.2+deb7u2", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libfreeradius-dev", ver:"2.1.12+dfsg-1.2+deb7u2", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libfreeradius2", ver:"2.1.12+dfsg-1.2+deb7u2", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
