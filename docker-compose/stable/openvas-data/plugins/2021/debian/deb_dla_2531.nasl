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
  script_oid("1.3.6.1.4.1.25623.1.0.892531");
  script_version("2021-02-02T09:53:24+0000");
  script_cve_id("CVE-2020-28473");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-02-02 09:53:24 +0000 (Tue, 02 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-01-25 10:11:33 +0000 (Mon, 25 Jan 2021)");
  script_name("Debian LTS: Security Advisory for python-bottle (DLA-2531-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/01/msg00019.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2531-1");
  script_xref(name:"Advisory-ID", value:"DLA-2531-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-bottle'
  package(s) announced via the DLA-2531-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The package src:python-bottle before 0.12.19 are vulnerable to
Web Cache Poisoning by using a vector called parameter cloaking.

When the attacker can separate query parameters using a
semicolon, they can cause a difference in the interpretation
of the request between the proxy (running with default configuration)
and the server. This can result in malicious requests being cached
as completely safe ones, as the proxy would usually not see the
semicolon as a separator, and therefore would not include it in a
cache key of an unkeyed parameter.");

  script_tag(name:"affected", value:"'python-bottle' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
0.12.13-1+deb9u1.

We recommend that you upgrade your python-bottle packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"python-bottle", ver:"0.12.13-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-bottle-doc", ver:"0.12.13-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-bottle", ver:"0.12.13-1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
