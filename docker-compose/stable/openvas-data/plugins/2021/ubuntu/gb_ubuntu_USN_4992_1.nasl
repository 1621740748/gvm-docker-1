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
  script_oid("1.3.6.1.4.1.25623.1.0.844980");
  script_version("2021-07-06T12:11:22+0000");
  script_cve_id("CVE-2020-14372", "CVE-2020-25632", "CVE-2020-27749", "CVE-2020-27779", "CVE-2021-20225", "CVE-2021-20233");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-07-06 12:11:22 +0000 (Tue, 06 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-06-19 03:00:23 +0000 (Sat, 19 Jun 2021)");
  script_name("Ubuntu: Security Advisory for grub2-signed (USN-4992-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU20\.04 LTS|UBUNTU18\.04 LTS|UBUNTU20\.10)");

  script_xref(name:"Advisory-ID", value:"USN-4992-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-June/006077.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grub2-signed'
  package(s) announced via the USN-4992-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"M�t� Kukri discovered that the acpi command in GRUB 2 allowed privileged
users to load crafted ACPI tables when secure boot is enabled. An attacker
could use this to bypass UEFI Secure Boot restrictions. (CVE-2020-14372)

Chris Coulson discovered that the rmmod command in GRUB 2 contained a use-
after-free vulnerability. A local attacker could use this to execute
arbitrary code and bypass UEFI Secure Boot restrictions. (CVE-2020-25632)

Chris Coulson discovered that a buffer overflow existed in the command line
parser in GRUB 2. A local attacker could use this to execute arbitrary code
and bypass UEFI Secure Boot restrictions. (CVE-2020-27749)

It was discovered that the cutmem command in GRUB 2 did not honor secure
boot locking. A local attacker could use this to execute arbitrary code and
bypass UEFI Secure Boot restrictions. (CVE-2020-27779)

It was discovered that the option parser in GRUB 2 contained a heap
overflow vulnerability. A local attacker could use this to execute
arbitrary code and bypass UEFI Secure Boot restrictions. (CVE-2021-20225)

It was discovered that the menu rendering implementation in GRUB 2 did not
properly calculate the amount of memory needed in some situations, leading
to out-of-bounds writes. A local attacker could use this to execute
arbitrary code and bypass UEFI Secure Boot restrictions. (CVE-2021-20233)");

  script_tag(name:"affected", value:"'grub2-signed' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64-bin", ver:"2.04-1ubuntu44.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64-signed", ver:"1.167.2+2.04-1ubuntu44.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64-bin", ver:"2.04-1ubuntu44.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64-signed", ver:"1.167.2+2.04-1ubuntu44.2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64-bin", ver:"2.04-1ubuntu44.1.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64-signed", ver:"1.167~18.04.5+2.04-1ubuntu44.1.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64-bin", ver:"2.04-1ubuntu44.1.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64-signed", ver:"1.167~18.04.5+2.04-1ubuntu44.1.2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64-bin", ver:"2.04-1ubuntu44.2", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64-signed", ver:"1.167.2+2.04-1ubuntu44.2", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64-bin", ver:"2.04-1ubuntu44.2", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64-signed", ver:"1.167.2+2.04-1ubuntu44.2", rls:"UBUNTU20.10"))) {
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