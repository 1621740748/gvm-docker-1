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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3250.1");
  script_cve_id("CVE-2018-14680", "CVE-2018-14681", "CVE-2018-14682", "CVE-2018-15378");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:35 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-26 11:45:00 +0000 (Mon, 26 Apr 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3250-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3250-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183250-1/");
  script_xref(name:"URL", value:"https://bugzilla.clamav.net/show_bug.cgi?id=12048");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the SUSE-SU-2018:3250-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for clamav fixes the following issues:

clamav was updated to version 0.100.2.

Following security issues were fixed:
CVE-2018-15378: Vulnerability in ClamAV's MEW unpacking feature that
 could allow an unauthenticated, remote attacker to cause a denial of
 service (DoS) condition on an affected device. (bsc#1110723)

CVE-2018-14680, CVE-2018-14681, CVE-2018-14682: more fixes for embedded
 libmspack. (bsc#1103040)

Following non-security issues were addressed:
Make freshclam more robust against lagging signature mirrors.

On-Access 'Extra Scanning', an opt-in minor feature of OnAccess scanning
 on Linux systems, has been disabled due to a known issue with resource
 cleanup OnAccessExtraScanning will be re-enabled in a future release
 when the issue is resolved. In the mean-time, users who enabled the
 feature in clamd.conf will see a warning informing them that the feature
 is not active. For details, see:
 [link moved to references]

Restore exit code compatibility of freshclam with versions before
 0.100.0 when the virus database is already up to date (bsc#1104457)");

  script_tag(name:"affected", value:"'clamav' package(s) on SUSE Linux Enterprise Module for Basesystem 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.100.2~3.6.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debuginfo", rpm:"clamav-debuginfo~0.100.2~3.6.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debugsource", rpm:"clamav-debugsource~0.100.2~3.6.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-devel", rpm:"clamav-devel~0.100.2~3.6.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav7", rpm:"libclamav7~0.100.2~3.6.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav7-debuginfo", rpm:"libclamav7-debuginfo~0.100.2~3.6.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclammspack0", rpm:"libclammspack0~0.100.2~3.6.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclammspack0-debuginfo", rpm:"libclammspack0-debuginfo~0.100.2~3.6.4", rls:"SLES15.0"))) {
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
