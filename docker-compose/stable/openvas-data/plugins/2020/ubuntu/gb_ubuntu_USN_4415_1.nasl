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
  script_oid("1.3.6.1.4.1.25623.1.0.844491");
  script_version("2021-07-09T11:00:55+0000");
  script_cve_id("CVE-2020-4067", "CVE-2020-6061", "CVE-2020-6062");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-09 11:00:55 +0000 (Fri, 09 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-08 19:15:00 +0000 (Wed, 08 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-07 03:00:38 +0000 (Tue, 07 Jul 2020)");
  script_name("Ubuntu: Security Advisory for coturn (USN-4415-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU19\.10|UBUNTU18\.04 LTS|UBUNTU16\.04 LTS|UBUNTU20\.04 LTS)");

  script_xref(name:"USN", value:"4415-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-July/005503.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'coturn'
  package(s) announced via the USN-4415-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Felix D�rre discovered that coTURN response buffer is not initialized properly.
An attacker could possibly use this issue to obtain sensitive information.
(CVE-2020-4067)

It was discovered that coTURN web server incorrectly handled HTTP POST requests.
An attacker could possibly use this issue to cause a denial of service, obtain
sensitive information or other unspecified impact.
(CVE-2020-6061, CVE-2020-6062)");

  script_tag(name:"affected", value:"'coturn' package(s) on Ubuntu 20.04 LTS, Ubuntu 19.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS.");

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

if(release == "UBUNTU19.10") {

  if(!isnull(res = isdpkgvuln(pkg:"coturn", ver:"4.5.1.1-1.1ubuntu0.19.10.1", rls:"UBUNTU19.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"coturn", ver:"4.5.0.7-1ubuntu2.18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"coturn", ver:"4.5.0.3-1ubuntu0.3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"coturn", ver:"4.5.1.1-1.1ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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