###############################################################################
# OpenVAS Vulnerability Test
#
# Auto-generated from advisory DSA 4208-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.704208");
  script_version("2021-06-21T03:34:17+0000");
  script_cve_id("CVE-2018-1122", "CVE-2018-1123", "CVE-2018-1124", "CVE-2018-1125", "CVE-2018-1126");
  script_name("Debian Security Advisory DSA 4208-1 (procps - security update)");
  script_tag(name:"last_modification", value:"2021-06-21 03:34:17 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-05-22 00:00:00 +0200 (Tue, 22 May 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-30 13:15:00 +0000 (Tue, 30 Jul 2019)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4208.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB[89]");
  script_tag(name:"affected", value:"procps on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), these problems have been fixed
in version 2:3.3.9-9+deb8u1.

For the stable distribution (stretch), these problems have been fixed in
version 2:3.3.12-3+deb9u1.

We recommend that you upgrade your procps packages.");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/procps");

  script_tag(name:"summary", value:"The Qualys Research Labs discovered multiple vulnerabilities in procps,
a set of command line and full screen utilities for browsing procfs. The
Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2018-1122
top read its configuration from the current working directory if no
$HOME was configured. If top were started from a directory writable
by the attacker (such as /tmp) this could result in local privilege
escalation.

CVE-2018-1123
Denial of service against the ps invocation of another user.

CVE-2018-1124
An integer overflow in the file2strvec() function of libprocps could
result in local privilege escalation.

CVE-2018-1125
A stack-based buffer overflow in pgrep could result in denial
of service for a user using pgrep for inspecting a specially
crafted process.

CVE-2018-1126
Incorrect integer size parameters used in wrappers for standard C
allocators could cause integer truncation and lead to integer
overflow issues.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libprocps-dev", ver:"2:3.3.12-3+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libprocps6", ver:"2:3.3.12-3+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"procps", ver:"2:3.3.12-3+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libprocps3", ver:"2:3.3.9-9+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libprocps3-dev", ver:"2:3.3.9-9+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"procps", ver:"2:3.3.9-9+deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
