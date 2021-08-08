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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2318.1");
  script_cve_id("CVE-2014-8146", "CVE-2014-8147");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-23 19:29:00 +0000 (Tue, 23 Apr 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2318-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2318-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172318-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icu' package(s) announced via the SUSE-SU-2017:2318-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"icu was updated to fix two security issues.
These security issues were fixed:
- CVE-2014-8147: The resolveImplicitLevels function in common/ubidi.c in
 the Unicode Bidirectional Algorithm implementation in ICU4C in
 International Components for Unicode (ICU) used an integer data type
 that is inconsistent with a header file, which allowed remote attackers
 to cause a denial of service (incorrect malloc followed by invalid free)
 or possibly execute arbitrary code via crafted text (bsc#929629).
- CVE-2014-8146: The resolveImplicitLevels function in common/ubidi.c in
 the Unicode Bidirectional Algorithm implementation in ICU4C in
 International Components for Unicode (ICU) did not properly track
 directionally isolated pieces of text, which allowed remote attackers to
 cause a denial of service (heap-based buffer overflow) or possibly
 execute arbitrary code via crafted text (bsc#929629).");

  script_tag(name:"affected", value:"'icu' package(s) on SUSE Linux Enterprise Workstation Extension 12-SP3, SUSE Linux Enterprise Workstation Extension 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Desktop 12-SP2, SUSE Container as a Service Platform ALL, OpenStack Cloud Magnum Orchestration 7.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"icu-debuginfo", rpm:"icu-debuginfo~52.1~8.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icu-debugsource", rpm:"icu-debugsource~52.1~8.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu-doc", rpm:"libicu-doc~52.1~8.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu52_1", rpm:"libicu52_1~52.1~8.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu52_1-data", rpm:"libicu52_1-data~52.1~8.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu52_1-debuginfo", rpm:"libicu52_1-debuginfo~52.1~8.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu52_1-32bit", rpm:"libicu52_1-32bit~52.1~8.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu52_1-debuginfo-32bit", rpm:"libicu52_1-debuginfo-32bit~52.1~8.3.1", rls:"SLES12.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"icu-debuginfo", rpm:"icu-debuginfo~52.1~8.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icu-debugsource", rpm:"icu-debugsource~52.1~8.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu-doc", rpm:"libicu-doc~52.1~8.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu52_1", rpm:"libicu52_1~52.1~8.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu52_1-data", rpm:"libicu52_1-data~52.1~8.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu52_1-debuginfo", rpm:"libicu52_1-debuginfo~52.1~8.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu52_1-32bit", rpm:"libicu52_1-32bit~52.1~8.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu52_1-debuginfo-32bit", rpm:"libicu52_1-debuginfo-32bit~52.1~8.3.1", rls:"SLES12.0SP2"))) {
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
