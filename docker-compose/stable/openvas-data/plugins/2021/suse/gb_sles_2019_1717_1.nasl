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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1717.1");
  script_cve_id("CVE-2019-12447", "CVE-2019-12448", "CVE-2019-12449", "CVE-2019-12795");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:22 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-08 00:15:00 +0000 (Mon, 08 Jul 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1717-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1717-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191717-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gvfs' package(s) announced via the SUSE-SU-2019:1717-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gvfs fixes the following issues:

Security issues fixed:
CVE-2019-12795: Fixed a vulnerability which could have allowed attacks
 via local D-Bus method calls (bsc#1137930).

CVE-2019-12447: Fixed an improper handling of file ownership in
 daemon/gvfsbackendadmin.c due to no use of setfsuid (bsc#1136986).

CVE-2019-12449: Fixed an improper handling of file's user and group
 ownership in daemon/gvfsbackendadmin.c (bsc#1136992).

CVE-2019-12448: Fixed race conditions in daemon/gvfsbackendadmin.c due
 to implementation
 of query_info_on_read/write at admin backend (bsc#1136981).

Other issue addressed:
Drop polkit rules files that are only relevant for wheel group
 (bsc#1125433).");

  script_tag(name:"affected", value:"'gvfs' package(s) on SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1, SUSE Linux Enterprise Module for Desktop Applications 15-SP1, SUSE Linux Enterprise Module for Desktop Applications 15.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"gvfs", rpm:"gvfs~1.34.2.1~4.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-backend-afc", rpm:"gvfs-backend-afc~1.34.2.1~4.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-backend-afc-debuginfo", rpm:"gvfs-backend-afc-debuginfo~1.34.2.1~4.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-backend-samba", rpm:"gvfs-backend-samba~1.34.2.1~4.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-backend-samba-debuginfo", rpm:"gvfs-backend-samba-debuginfo~1.34.2.1~4.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-backends", rpm:"gvfs-backends~1.34.2.1~4.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-backends-debuginfo", rpm:"gvfs-backends-debuginfo~1.34.2.1~4.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-debuginfo", rpm:"gvfs-debuginfo~1.34.2.1~4.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-debugsource", rpm:"gvfs-debugsource~1.34.2.1~4.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-devel", rpm:"gvfs-devel~1.34.2.1~4.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-fuse", rpm:"gvfs-fuse~1.34.2.1~4.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-fuse-debuginfo", rpm:"gvfs-fuse-debuginfo~1.34.2.1~4.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-lang", rpm:"gvfs-lang~1.34.2.1~4.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"gvfs", rpm:"gvfs~1.34.2.1~4.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-backend-afc", rpm:"gvfs-backend-afc~1.34.2.1~4.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-backend-afc-debuginfo", rpm:"gvfs-backend-afc-debuginfo~1.34.2.1~4.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-backend-samba", rpm:"gvfs-backend-samba~1.34.2.1~4.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-backend-samba-debuginfo", rpm:"gvfs-backend-samba-debuginfo~1.34.2.1~4.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-backends", rpm:"gvfs-backends~1.34.2.1~4.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-backends-debuginfo", rpm:"gvfs-backends-debuginfo~1.34.2.1~4.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-debuginfo", rpm:"gvfs-debuginfo~1.34.2.1~4.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-debugsource", rpm:"gvfs-debugsource~1.34.2.1~4.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-devel", rpm:"gvfs-devel~1.34.2.1~4.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-fuse", rpm:"gvfs-fuse~1.34.2.1~4.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-fuse-debuginfo", rpm:"gvfs-fuse-debuginfo~1.34.2.1~4.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-lang", rpm:"gvfs-lang~1.34.2.1~4.13.1", rls:"SLES15.0"))) {
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
