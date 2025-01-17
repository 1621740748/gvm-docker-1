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
  script_oid("1.3.6.1.4.1.25623.1.0.844490");
  script_version("2021-07-13T02:01:14+0000");
  script_cve_id("CVE-2017-12133", "CVE-2017-18269", "CVE-2018-11236", "CVE-2018-11237", "CVE-2018-19591", "CVE-2018-6485", "CVE-2019-19126", "CVE-2019-9169", "CVE-2020-10029", "CVE-2020-1751", "CVE-2020-1752");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-13 02:01:14 +0000 (Tue, 13 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-09 20:15:00 +0000 (Thu, 09 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-07 03:00:30 +0000 (Tue, 07 Jul 2020)");
  script_name("Ubuntu: Security Advisory for glibc (USN-4416-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU19\.10|UBUNTU18\.04 LTS|UBUNTU16\.04 LTS)");

  script_xref(name:"USN", value:"4416-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-July/005505.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc'
  package(s) announced via the USN-4416-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Florian Weimer discovered that the GNU C Library incorrectly handled
certain memory operations. A remote attacker could use this issue to cause
the GNU C Library to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 16.04 LTS.
(CVE-2017-12133)

It was discovered that the GNU C Library incorrectly handled certain
SSE2-optimized memmove operations. A remote attacker could use this issue
to cause the GNU C Library to crash, resulting in a denial of service, or
possibly execute arbitrary code. This issue only affected Ubuntu 16.04 LTS.
(CVE-2017-18269)

It was discovered that the GNU C Library incorrectly handled certain
pathname operations. A remote attacker could use this issue to cause the
GNU C Library to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 18.04 LTS.
(CVE-2018-11236)

It was discovered that the GNU C Library incorrectly handled certain
AVX-512-optimized mempcpy operations. A remote attacker could use this
issue to cause the GNU C Library to crash, resulting in a denial of
service, or possibly execute arbitrary code. This issue only affected
Ubuntu 18.04 LTS. (CVE-2018-11237)

It was discovered that the GNU C Library incorrectly handled certain
hostname loookups. A remote attacker could use this issue to cause the GNU
C Library to crash, resulting in a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 18.04 LTS. (CVE-2018-19591)

Jakub Wilk discovered that the GNU C Library incorrectly handled certain
memalign functions. A remote attacker could use this issue to cause the GNU
C Library to crash, resulting in a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 16.04 LTS. (CVE-2018-6485)

It was discovered that the GNU C Library incorrectly ignored the
LD_PREFER_MAP_32BIT_EXEC environment variable after security transitions. A
local attacker could use this issue to bypass ASLR restrictions.
(CVE-2019-19126)

It was discovered that the GNU C Library incorrectly handled certain
regular expressions. A remote attacker could possibly use this issue to
cause the GNU C Library to crash, resulting in a denial of service. This
issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2019-9169)

It was discovered that the GNU C Library incorrectly handled certain
bit patterns. A remote attacker could use this issue to cause the GNU C
Library to crash, resulting in a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 16.04 LTS a ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'glibc' package(s) on Ubuntu 19.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libc6", ver:"2.30-0ubuntu2.2", rls:"UBUNTU19.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libc6", ver:"2.27-3ubuntu1.2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libc6", ver:"2.23-0ubuntu11.2", rls:"UBUNTU16.04 LTS"))) {
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