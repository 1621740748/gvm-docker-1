# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892390");
  script_version("2021-07-23T11:01:09+0000");
  script_cve_id("CVE-2019-18848");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-01 15:15:00 +0000 (Thu, 01 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-02 03:00:10 +0000 (Fri, 02 Oct 2020)");
  script_name("Debian LTS: Security Advisory for ruby-json-jwt (DLA-2390-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/10/msg00001.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2390-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/944850");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby-json-jwt'
  package(s) announced via the DLA-2390-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The json-jwt gem before 1.11.0 for Ruby lacks an element
count during the splitting of a JWE string.

Therefore, there was a need to explicitly specify the number
of elements when splitting a JWE string.");

  script_tag(name:"affected", value:"'ruby-json-jwt' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
1.6.2-1+deb9u2.

We recommend that you upgrade your ruby-json-jwt packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"ruby-json-jwt", ver:"1.6.2-1+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
