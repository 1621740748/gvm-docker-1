# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892600");
  script_version("2021-03-26T07:27:18+0000");
  script_cve_id("CVE-2021-27291");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-03-26 07:27:18 +0000 (Fri, 26 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-20 04:00:09 +0000 (Sat, 20 Mar 2021)");
  script_name("Debian LTS: Security Advisory for pygments (DLA-2600-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/03/msg00024.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2600-1");
  script_xref(name:"Advisory-ID", value:"DLA-2600-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pygments'
  package(s) announced via the DLA-2600-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a series of denial of service
vulnerabilities in Pygments, a popular syntax highlighting library
for Python.

A number of regular expressions had exponential or cubic worst-case
complexity which could cause a remote denial of service (DoS) when
provided with malicious input.");

  script_tag(name:"affected", value:"'pygments' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 'Stretch', this problem has been fixed in version
2.2.0+dfsg-1+deb9u2.

We recommend that you upgrade your pygments packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"python-pygments", ver:"2.2.0+dfsg-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-pygments-doc", ver:"2.2.0+dfsg-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-pygments", ver:"2.2.0+dfsg-1+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
