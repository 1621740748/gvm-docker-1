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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1190.1");
  script_cve_id("CVE-2021-1252", "CVE-2021-1404", "CVE-2021-1405");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-14 19:56:00 +0000 (Wed, 14 Apr 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1190-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0|SLES15\.0SP3|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1190-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211190-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the SUSE-SU-2021:1190-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for clamav fixes the following issues:

CVE-2021-1252: Fix for Excel XLM parser infinite loop. (bsc#1184532)

CVE-2021-1404: Fix for PDF parser buffer over-read, possible crash.
 (bsc#1184533)

CVE-2021-1405: Fix for mail parser NULL-dereference crash. (bsc#1184534)

Fix errors when scanning files > 4G (bsc#1181256)

Update clamav.keyring

Update to 0.103.2");

  script_tag(name:"affected", value:"'clamav' package(s) on SUSE Manager Server 4.0, SUSE Manager Retail Branch Server 4.0, SUSE Manager Proxy 4.0, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15, SUSE Enterprise Storage 6, SUSE CaaS Platform 4.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.103.2~3.26.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debuginfo", rpm:"clamav-debuginfo~0.103.2~3.26.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debugsource", rpm:"clamav-debugsource~0.103.2~3.26.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-devel", rpm:"clamav-devel~0.103.2~3.26.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav9", rpm:"libclamav9~0.103.2~3.26.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav9-debuginfo", rpm:"libclamav9-debuginfo~0.103.2~3.26.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreshclam2", rpm:"libfreshclam2~0.103.2~3.26.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreshclam2-debuginfo", rpm:"libfreshclam2-debuginfo~0.103.2~3.26.1", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.103.2~3.26.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debuginfo", rpm:"clamav-debuginfo~0.103.2~3.26.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debugsource", rpm:"clamav-debugsource~0.103.2~3.26.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-devel", rpm:"clamav-devel~0.103.2~3.26.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav9", rpm:"libclamav9~0.103.2~3.26.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav9-debuginfo", rpm:"libclamav9-debuginfo~0.103.2~3.26.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreshclam2", rpm:"libfreshclam2~0.103.2~3.26.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreshclam2-debuginfo", rpm:"libfreshclam2-debuginfo~0.103.2~3.26.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.103.2~3.26.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debuginfo", rpm:"clamav-debuginfo~0.103.2~3.26.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debugsource", rpm:"clamav-debugsource~0.103.2~3.26.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-devel", rpm:"clamav-devel~0.103.2~3.26.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav9", rpm:"libclamav9~0.103.2~3.26.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav9-debuginfo", rpm:"libclamav9-debuginfo~0.103.2~3.26.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreshclam2", rpm:"libfreshclam2~0.103.2~3.26.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreshclam2-debuginfo", rpm:"libfreshclam2-debuginfo~0.103.2~3.26.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.103.2~3.26.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debuginfo", rpm:"clamav-debuginfo~0.103.2~3.26.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debugsource", rpm:"clamav-debugsource~0.103.2~3.26.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-devel", rpm:"clamav-devel~0.103.2~3.26.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav9", rpm:"libclamav9~0.103.2~3.26.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav9-debuginfo", rpm:"libclamav9-debuginfo~0.103.2~3.26.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreshclam2", rpm:"libfreshclam2~0.103.2~3.26.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreshclam2-debuginfo", rpm:"libfreshclam2-debuginfo~0.103.2~3.26.1", rls:"SLES15.0SP2"))) {
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
