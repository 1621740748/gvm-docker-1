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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2145.1");
  script_cve_id("CVE-2015-8872", "CVE-2016-4804");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-30 18:15:00 +0000 (Sat, 30 May 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2145-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2145-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162145-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dosfstools' package(s) announced via the SUSE-SU-2016:2145-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"dosfstools was updated to fix two security issues.
These security issues were fixed:
- CVE-2015-8872: The set_fat function in fat.c in dosfstools might have
 allowed attackers to corrupt a FAT12 filesystem or cause a denial of
 service (invalid memory read and crash) by writing an odd number of
 clusters to the third to last entry on a FAT12 filesystem, which
 triggers an 'off-by-two error (bsc#980364).
- CVE-2016-4804: The read_boot function in boot.c in dosfstools allowed
 attackers to cause a denial of service (crash) via a crafted filesystem,
 which triggers a heap-based buffer overflow in the (1) read_fat function
 or an out-of-bounds heap read in (2) get_fat function (bsc#980377).
This non-security issue was fixed:
- bsc#912607: Attempt to rename root dir in fsck due to uninitialized
 fields.");

  script_tag(name:"affected", value:"'dosfstools' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Desktop 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"dosfstools", rpm:"dosfstools~3.0.26~6.5", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dosfstools-debuginfo", rpm:"dosfstools-debuginfo~3.0.26~6.5", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dosfstools-debugsource", rpm:"dosfstools-debugsource~3.0.26~6.5", rls:"SLES12.0SP1"))) {
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
