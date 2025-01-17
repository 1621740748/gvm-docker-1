# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 2914-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.702914");
  script_version("2021-04-26T08:46:56+0000");
  script_cve_id("CVE-2014-2983");
  script_name("Debian Security Advisory DSA 2914-1 (drupal6 - security update)");
  script_tag(name:"last_modification", value:"2021-04-26 08:46:56 +0000 (Mon, 26 Apr 2021)");
  script_tag(name:"creation_date", value:"2014-04-25 00:00:00 +0200 (Fri, 25 Apr 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2914.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");
  script_tag(name:"affected", value:"drupal6 on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (squeeze), this problem has been fixed in
version 6.31-1.

We recommend that you upgrade your drupal6 packages.");
  script_tag(name:"summary", value:"An information disclosure vulnerability was discovered in Drupal, a
fully-featured content management framework. When pages are cached for
anonymous users, form state may leak between anonymous users. Sensitive
or private information recorded for one anonymous user could thus be
disclosed to other users interacting with the same form at the same
time.

This security update introduces small API changes, see the upstream
advisory at drupal.org/SA-CORE-2014-002
for further information.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"drupal6", ver:"6.31-1", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}