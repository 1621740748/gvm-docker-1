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
  script_oid("1.3.6.1.4.1.25623.1.0.845003");
  script_version("2021-08-03T07:24:09+0000");
  script_cve_id("CVE-2021-33910", "CVE-2020-13529");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-08-03 07:24:09 +0000 (Tue, 03 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-07-21 03:00:57 +0000 (Wed, 21 Jul 2021)");
  script_name("Ubuntu: Security Advisory for systemd (USN-5013-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU20\.04 LTS|UBUNTU18\.04 LTS|UBUNTU20\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5013-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-July/006106.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd'
  package(s) announced via the USN-5013-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that systemd incorrectly handled certain mount paths. A
local attacker could possibly use this issue to cause systemd to crash,
resulting in a denial of service. (CVE-2021-33910)

Mitchell Frank discovered that systemd incorrectly handled DHCP FORCERENEW
packets. A remote attacker could possibly use this issue to reconfigure
servers. (CVE-2020-13529)");

  script_tag(name:"affected", value:"'systemd' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"systemd", ver:"245.4-4ubuntu3.10", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"systemd", ver:"237-3ubuntu10.49", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.10") {

  if(!isnull(res = isdpkgvuln(pkg:"systemd", ver:"246.6-1ubuntu1.7", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);