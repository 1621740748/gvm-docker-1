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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1662.1");
  script_cve_id("CVE-2017-1000456", "CVE-2017-14517", "CVE-2017-14518", "CVE-2017-14520", "CVE-2017-14617", "CVE-2017-14928", "CVE-2017-14975", "CVE-2017-14976", "CVE-2017-14977", "CVE-2017-15565", "CVE-2017-9865");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-30 17:54:00 +0000 (Tue, 30 Apr 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1662-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1662-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181662-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler' package(s) announced via the SUSE-SU-2018:1662-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for poppler fixes the following issues:
These security issues were fixed:
- CVE-2017-14517: Prevent NULL Pointer dereference in the
 XRef::parseEntry() function via a crafted PDF document (bsc#1059066).
- CVE-2017-9865: Fixed a stack-based buffer overflow vulnerability in
 GfxState.cc that would have allowed attackers to facilitate a
 denial-of-service attack via specially crafted PDF documents.
 (bsc#1045939)
- CVE-2017-14518: Remedy a floating point exception in
 isImageInterpolationRequired() that could have been exploited using a
 specially crafted PDF document. (bsc#1059101)
- CVE-2017-14520: Remedy a floating point exception in
 Splash::scaleImageYuXd() that could have been exploited using a
 specially crafted PDF document. (bsc#1059155)
- CVE-2017-14617: Fixed a floating point exception in Stream.cc, which may
 lead to a potential attack when handling malicious PDF files.
 (bsc#1060220)
- CVE-2017-14928: Fixed a NULL Pointer dereference in
 AnnotRichMedia::Configuration::Configuration() in Annot.cc, which may
 lead to a potential attack when handling malicious PDF files.
 (bsc#1061092)
- CVE-2017-14975: Fixed a NULL pointer dereference vulnerability, that
 existed because a data structure in FoFiType1C.cc was not initialized,
 which allowed an attacker to launch a denial of service attack.
 (bsc#1061263)
- CVE-2017-14976: Fixed a heap-based buffer over-read vulnerability in
 FoFiType1C.cc that occurred when an out-of-bounds font dictionary index
 was encountered, which allowed an attacker to launch a denial of service
 attack. (bsc#1061264)
- CVE-2017-14977: Fixed a NULL pointer dereference vulnerability in the
 FoFiTrueType::getCFFBlock() function in FoFiTrueType.cc that occurred
 due to lack of validation of a table pointer, which allows an attacker
 to launch a denial of service attack. (bsc#1061265)
- CVE-2017-15565: Prevent NULL Pointer dereference in the
 GfxImageColorMap::getGrayLine() function via a crafted PDF document
 (bsc#1064593).
- CVE-2017-1000456: Validate boundaries in TextPool::addWord to prevent
 overflows in subsequent calculations (bsc#1074453).");

  script_tag(name:"affected", value:"'poppler' package(s) on SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Desktop 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8", rpm:"libpoppler-glib8~0.43.0~16.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-debuginfo", rpm:"libpoppler-glib8-debuginfo~0.43.0~16.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt4-4", rpm:"libpoppler-qt4-4~0.43.0~16.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt4-4-debuginfo", rpm:"libpoppler-qt4-4-debuginfo~0.43.0~16.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler60", rpm:"libpoppler60~0.43.0~16.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler60-debuginfo", rpm:"libpoppler60-debuginfo~0.43.0~16.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-debugsource", rpm:"poppler-debugsource~0.43.0~16.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-qt-debugsource", rpm:"poppler-qt-debugsource~0.43.0~16.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-tools", rpm:"poppler-tools~0.43.0~16.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-tools-debuginfo", rpm:"poppler-tools-debuginfo~0.43.0~16.15.1", rls:"SLES12.0SP3"))) {
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
