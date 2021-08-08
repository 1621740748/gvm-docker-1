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
  script_oid("1.3.6.1.4.1.25623.1.0.844863");
  script_version("2021-03-30T06:46:39+0000");
  script_cve_id("CVE-2021-25289", "CVE-2021-25291", "CVE-2021-25290", "CVE-2021-25292", "CVE-2021-25293", "CVE-2021-27921", "CVE-2021-27922", "CVE-2021-27923");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-03-30 06:46:39 +0000 (Tue, 30 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-12 04:00:20 +0000 (Fri, 12 Mar 2021)");
  script_name("Ubuntu: Security Advisory for pillow (USN-4763-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU20\.04 LTS|UBUNTU18\.04 LTS|UBUNTU16\.04 LTS|UBUNTU20\.10)");

  script_xref(name:"Advisory-ID", value:"USN-4763-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-March/005928.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pillow'
  package(s) announced via the USN-4763-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Pillow incorrectly handled certain Tiff image files.
If a user or automated system were tricked into opening a specially-crafted
Tiff file, a remote attacker could cause Pillow to crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 20.04 LTS and Ubuntu 20.10. (CVE-2021-25289,
CVE-2021-25291)

It was discovered that Pillow incorrectly handled certain Tiff image files.
If a user or automated system were tricked into opening a specially-crafted
Tiff file, a remote attacker could cause Pillow to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2021-25290)

It was discovered that Pillow incorrectly handled certain PDF files. If a
user or automated system were tricked into opening a specially-crafted
PDF file, a remote attacker could cause Pillow to hang, resulting in a
denial of service. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04
LTS, and Ubuntu 20.10. (CVE-2021-25292)

It was discovered that Pillow incorrectly handled certain SGI image files.
If a user or automated system were tricked into opening a specially-crafted
SGI file, a remote attacker could possibly cause Pillow to crash,
resulting in a denial of service. This issue only affected Ubuntu 18.04
LTS, Ubuntu 20.04 LTS, and Ubuntu 20.10. (CVE-2021-25293)

Jiayi Lin, Luke Shaffer, Xinran Xie, and Akshay Ajayan discovered that
Pillow incorrectly handled certain BLP files. If a user or automated system
were tricked into opening a specially-crafted BLP file, a remote attacker
could possibly cause Pillow to consume resources, resulting in a denial of
service. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and
Ubuntu 20.10. (CVE-2021-27921)

Jiayi Lin, Luke Shaffer, Xinran Xie, and Akshay Ajayan discovered that
Pillow incorrectly handled certain ICNS files. If a user or automated
system were tricked into opening a specially-crafted ICNS file, a remote
attacker could possibly cause Pillow to consume resources, resulting in a
denial of service. (CVE-2021-27922)

Jiayi Lin, Luke Shaffer, Xinran Xie, and Akshay Ajayan discovered that
Pillow incorrectly handled certain ICO files. If a user or automated
system were tricked into opening a specially-crafted ICO file, a remote
attacker could possibly cause Pillow to consume resources, resulting in a
denial of service. (CVE-2021-27922)");

  script_tag(name:"affected", value:"'pillow' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python3-pil", ver:"7.0.0-4ubuntu0.3", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python-pil", ver:"5.1.0-1ubuntu0.5", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-pil", ver:"5.1.0-1ubuntu0.5", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python-pil", ver:"3.1.2-0ubuntu1.6", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-pil", ver:"3.1.2-0ubuntu1.6", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-pil", ver:"7.2.0-1ubuntu0.2", rls:"UBUNTU20.10"))) {
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