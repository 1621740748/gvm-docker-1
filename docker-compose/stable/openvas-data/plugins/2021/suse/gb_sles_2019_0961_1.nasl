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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0961.1");
  script_cve_id("CVE-2019-9636");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-29 14:15:00 +0000 (Thu, 29 Oct 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0961-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4|SLES12\.0SP3|SLES12\.0SP2|SLES12\.0SP1|SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0961-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190961-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3' package(s) announced via the SUSE-SU-2019:0961-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python3 fixes the following issues:

Security issue fixed:
CVE-2019-9636: Fixed an information disclosure because of incorrect
 handling of Unicode encoding during NFKC normalization (bsc#1129346).");

  script_tag(name:"affected", value:"'python3' package(s) on SUSE OpenStack Cloud 7, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP1, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Module for Web Scripting 12, SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Desktop 12-SP3, SUSE Enterprise Storage 4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libpython3_4m1_0", rpm:"libpython3_4m1_0~3.4.6~25.24.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_4m1_0-debuginfo", rpm:"libpython3_4m1_0-debuginfo~3.4.6~25.24.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.4.6~25.24.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base", rpm:"python3-base~3.4.6~25.24.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base-debuginfo", rpm:"python3-base-debuginfo~3.4.6~25.24.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base-debugsource", rpm:"python3-base-debugsource~3.4.6~25.24.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-curses", rpm:"python3-curses~3.4.6~25.24.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-curses-debuginfo", rpm:"python3-curses-debuginfo~3.4.6~25.24.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-debuginfo", rpm:"python3-debuginfo~3.4.6~25.24.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-debugsource", rpm:"python3-debugsource~3.4.6~25.24.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libpython3_4m1_0", rpm:"libpython3_4m1_0~3.4.6~25.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_4m1_0-debuginfo", rpm:"libpython3_4m1_0-debuginfo~3.4.6~25.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.4.6~25.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base", rpm:"python3-base~3.4.6~25.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base-debuginfo", rpm:"python3-base-debuginfo~3.4.6~25.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base-debugsource", rpm:"python3-base-debugsource~3.4.6~25.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-curses", rpm:"python3-curses~3.4.6~25.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-curses-debuginfo", rpm:"python3-curses-debuginfo~3.4.6~25.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-debuginfo", rpm:"python3-debuginfo~3.4.6~25.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-debugsource", rpm:"python3-debugsource~3.4.6~25.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libpython3_4m1_0", rpm:"libpython3_4m1_0~3.4.6~25.24.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_4m1_0-debuginfo", rpm:"libpython3_4m1_0-debuginfo~3.4.6~25.24.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.4.6~25.24.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base", rpm:"python3-base~3.4.6~25.24.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base-debuginfo", rpm:"python3-base-debuginfo~3.4.6~25.24.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base-debugsource", rpm:"python3-base-debugsource~3.4.6~25.24.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-curses", rpm:"python3-curses~3.4.6~25.24.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-curses-debuginfo", rpm:"python3-curses-debuginfo~3.4.6~25.24.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-debuginfo", rpm:"python3-debuginfo~3.4.6~25.24.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-debugsource", rpm:"python3-debugsource~3.4.6~25.24.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libpython3_4m1_0", rpm:"libpython3_4m1_0~3.4.6~25.24.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_4m1_0-debuginfo", rpm:"libpython3_4m1_0-debuginfo~3.4.6~25.24.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.4.6~25.24.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base", rpm:"python3-base~3.4.6~25.24.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base-debuginfo", rpm:"python3-base-debuginfo~3.4.6~25.24.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base-debugsource", rpm:"python3-base-debugsource~3.4.6~25.24.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-debuginfo", rpm:"python3-debuginfo~3.4.6~25.24.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-debugsource", rpm:"python3-debugsource~3.4.6~25.24.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"libpython3_4m1_0", rpm:"libpython3_4m1_0~3.4.6~25.24.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_4m1_0-debuginfo", rpm:"libpython3_4m1_0-debuginfo~3.4.6~25.24.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.4.6~25.24.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base", rpm:"python3-base~3.4.6~25.24.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base-debuginfo", rpm:"python3-base-debuginfo~3.4.6~25.24.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base-debugsource", rpm:"python3-base-debugsource~3.4.6~25.24.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-debuginfo", rpm:"python3-debuginfo~3.4.6~25.24.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-debugsource", rpm:"python3-debugsource~3.4.6~25.24.1", rls:"SLES12.0"))) {
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
