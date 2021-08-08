# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852413");
  script_version("2020-03-13T07:50:12+0000");
  script_cve_id("CVE-2018-12181", "CVE-2019-0160");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-03-13 07:50:12 +0000 (Fri, 13 Mar 2020)");
  script_tag(name:"creation_date", value:"2019-04-09 02:01:05 +0000 (Tue, 09 Apr 2019)");
  script_name("openSUSE: Security Advisory for ovmf (openSUSE-SU-2019:1172-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2019:1172-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-04/msg00048.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ovmf'
  package(s) announced via the openSUSE-SU-2019:1172-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ovmf fixes the following issues:

  Security issues fixed:

  - CVE-2019-0160: Fixed multiple buffer overflows in UDF-related codes in
  MdeModulePkg\Universal\Disk\PartitionDxe\Udf.c and
  MdeModulePkg\Universal\Disk\UdfDxe (bsc#1130267).

  - CVE-2018-12181: Fixed a stack buffer overflow in the HII database when a
  corrupted Bitmap was used (bsc#1128503).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1172=1");

  script_tag(name:"affected", value:"'ovmf' package(s) on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"ovmf", rpm:"ovmf~2017+git1510945757.b2662641d5~lp150.4.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovmf-tools", rpm:"ovmf-tools~2017+git1510945757.b2662641d5~lp150.4.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ovmf-ia32", rpm:"qemu-ovmf-ia32~2017+git1510945757.b2662641d5~lp150.4.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ovmf-x86-64", rpm:"qemu-ovmf-x86-64~2017+git1510945757.b2662641d5~lp150.4.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ovmf-x86-64-debug", rpm:"qemu-ovmf-x86-64-debug~2017+git1510945757.b2662641d5~lp150.4.16.1", rls:"openSUSELeap15.0"))) {
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
