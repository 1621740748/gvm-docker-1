# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.891996");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2019-14857");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-11-26 12:49:51 +0000 (Tue, 26 Nov 2019)");
  script_name("Debian LTS: Security Advisory for libapache2-mod-auth-openidc (DLA-1996-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/11/msg00016.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1996-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/942165");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libapache2-mod-auth-openidc'
  package(s) announced via the DLA-1996-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A security vulnerability was found in libapache2-mod-auth-openidc, the
OpenID Connect authentication module for the Apache HTTP server.

Insufficient validation of URLs leads to an Open Redirect
vulnerability. An attacker may trick a victim into providing credentials
for an OpenID provider by forwarding the request to an illegitimate
website.");

  script_tag(name:"affected", value:"'libapache2-mod-auth-openidc' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', this problem has been fixed in version
1.6.0-1+deb8u2.

We recommend that you upgrade your libapache2-mod-auth-openidc packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-auth-openidc", ver:"1.6.0-1+deb8u2", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
