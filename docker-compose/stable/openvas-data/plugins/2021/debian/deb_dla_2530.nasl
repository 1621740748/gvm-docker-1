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
  script_oid("1.3.6.1.4.1.25623.1.0.892530");
  script_version("2021-01-25T10:11:31+0000");
  script_cve_id("CVE-2020-36193");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-01-25 10:11:31 +0000 (Mon, 25 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-25 10:11:31 +0000 (Mon, 25 Jan 2021)");
  script_name("Debian LTS: Security Advisory for drupal7 (DLA-2530-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/01/msg00018.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2530-1");
  script_xref(name:"Advisory-ID", value:"DLA-2530-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'drupal7'
  package(s) announced via the DLA-2530-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Drupal identified a vulnerability in the version of the Archive_Tar
library it bundles (CVE-2020-36193), which allows out-of-path
extraction vulnerabilities, granting it the Drupal Security Advisory
ID SA-CORE-2021-001:");

  script_tag(name:"affected", value:"'drupal7' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 'Stretch', the fix to this issue was backported in
version 7.52-2+deb9u14.

We recommend you upgrade your drupal7 package.

For detailed security status of drupal7, please refer to its security
tracker page:");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"drupal7", ver:"7.52-2+deb9u14", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
