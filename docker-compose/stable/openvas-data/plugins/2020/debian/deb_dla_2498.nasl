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
  script_oid("1.3.6.1.4.1.25623.1.0.892498");
  script_version("2021-07-28T02:00:54+0000");
  script_cve_id("CVE-2018-1311");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-28 02:00:54 +0000 (Wed, 28 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-28 12:15:00 +0000 (Fri, 28 May 2021)");
  script_tag(name:"creation_date", value:"2020-12-18 04:00:22 +0000 (Fri, 18 Dec 2020)");
  script_name("Debian LTS: Security Advisory for xerces-c (DLA-2498-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/12/msg00025.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2498-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/947431");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xerces-c'
  package(s) announced via the DLA-2498-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The UK's National Cyber Security Centre (NCSC) discovered that
Xerces-C, a validating XML parser library for C++, contains a
use-after-free error triggered during the scanning of external
DTDs. An attacker could cause a Denial of Service (DoS) and possibly
achieve remote code execution. This flaw has not been addressed in the
maintained version of the library and has no complete mitigation. The
first is provided by this update which fixes the use-after-free
vulnerability at the expense of a memory leak. The other is to disable
DTD processing, which can be accomplished via the DOM using a standard
parser feature, or via SAX using the XERCES_DISABLE_DTD environment
variable.");

  script_tag(name:"affected", value:"'xerces-c' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
3.1.4+debian-2+deb9u2.

We recommend that you upgrade your xerces-c packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libxerces-c-dev", ver:"3.1.4+debian-2+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxerces-c-doc", ver:"3.1.4+debian-2+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxerces-c-samples", ver:"3.1.4+debian-2+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxerces-c3.1", ver:"3.1.4+debian-2+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
