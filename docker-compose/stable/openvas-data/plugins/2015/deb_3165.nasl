# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 3165-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703165");
  script_version("2021-06-17T07:22:39+0000");
  script_cve_id("CVE-2015-1877");
  script_name("Debian Security Advisory DSA 3165-1 (xdg-utils - security update)");
  script_tag(name:"last_modification", value:"2021-06-17 07:22:39 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"creation_date", value:"2015-02-21 00:00:00 +0100 (Sat, 21 Feb 2015)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3165.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"xdg-utils on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy),
this problem has been fixed in version 1.1.0~rc1+git20111210-6+deb7u3.

For the upcoming stable (jessie) and unstable (sid) distributions,
this problem will be fixed soon.

We recommend that you upgrade your xdg-utils packages.");
  script_tag(name:"summary", value:"Jiri Horner discovered a way to cause
xdg-open, a tool that automatically opens URLs in a user's preferred application,
to execute arbitrary commands remotely.

This problem only affects /bin/sh implementations that don't sanitize
local variables. Dash, which is the default /bin/sh in Debian is
affected. Bash as /bin/sh is known to be unaffected.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"xdg-utils", ver:"1.1.0~rc1+git20111210-6+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}