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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2780.1");
  script_cve_id("CVE-2018-11440", "CVE-2018-11577", "CVE-2018-11683", "CVE-2018-11684", "CVE-2018-11685", "CVE-2018-12085");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2780-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2780-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182780-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'liblouis' package(s) announced via the SUSE-SU-2018:2780-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for liblouis, python-louis, python3-louis fixes the following issues:

Security issues fixed:
CVE-2018-11440: Fixed a stack-based buffer overflow in the function
 parseChars() in compileTranslationTable.c (bsc#1095189)

CVE-2018-11577: Fixed a segmentation fault in lou_logPrint in logging.c
 (bsc#1095945)

CVE-2018-11683: Fixed a stack-based buffer overflow in the function
 parseChars() in compileTranslationTable.c (different vulnerability than
 CVE-2018-11440) (bsc#1095827)

CVE-2018-11684: Fixed stack-based buffer overflow in the function
 includeFile() in compileTranslationTable.c (bsc#1095826)

CVE-2018-11685: Fixed a stack-based buffer overflow in the function
 compileHyphenation() in compileTranslationTable.c (bsc#1095825)

CVE-2018-12085: Fixed a stack-based buffer overflow in the function
 parseChars() in compileTranslationTable.c (different vulnerability than
 CVE-2018-11440) (bsc#1097103)");

  script_tag(name:"affected", value:"'liblouis' package(s) on SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Desktop 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"liblouis-data", rpm:"liblouis-data~2.6.4~6.6.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblouis-debugsource", rpm:"liblouis-debugsource~2.6.4~6.6.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblouis9", rpm:"liblouis9~2.6.4~6.6.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblouis9-debuginfo", rpm:"liblouis9-debuginfo~2.6.4~6.6.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-louis", rpm:"python-louis~2.6.4~6.6.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-louis", rpm:"python3-louis~2.6.4~6.6.1", rls:"SLES12.0SP3"))) {
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
