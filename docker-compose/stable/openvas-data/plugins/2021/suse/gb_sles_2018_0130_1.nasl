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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0130.1");
  script_cve_id("CVE-2017-10800", "CVE-2017-11141", "CVE-2017-11529", "CVE-2017-11644", "CVE-2017-11724", "CVE-2017-12434", "CVE-2017-12564", "CVE-2017-12667", "CVE-2017-12670", "CVE-2017-12672", "CVE-2017-12675", "CVE-2017-13060", "CVE-2017-13146", "CVE-2017-13648", "CVE-2017-13658", "CVE-2017-14326", "CVE-2017-14533", "CVE-2017-17881", "CVE-2017-18022", "CVE-2018-5246", "CVE-2018-5247");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-14 17:44:00 +0000 (Wed, 14 Oct 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0130-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0130-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180130-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2018:0130-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes several issues.
These security issues were fixed:
- CVE-2018-5246: Fixed memory leak vulnerability in ReadPATTERNImage in
 coders/pattern.c (bsc#1074973)
- CVE-2017-18022: Fixed memory leak vulnerability in MontageImageCommand
 in MagickWand/montage.c (bsc#1074975)
- CVE-2018-5247: Fixed memory leak vulnerability in ReadRLAImage in
 coders/rla.c (bsc#1074969)
- CVE-2017-12672: Fixed a memory leak vulnerability in the function
 ReadMATImage in coders/mat.c, which allowed attackers to cause a denial
 of service (bsc#1052720)
- CVE-2017-13060: Fixed a memory leak vulnerability in the function
 ReadMATImage in coders/mat.c, which allowed attackers to cause a denial
 of service via a crafted file (bsc#1055065)
- CVE-2017-11724: Fixed a memory leak vulnerability in the function
 ReadMATImage in coders/mat.c involving the quantum_info and clone_info
 data structures (bsc#1051446)
- CVE-2017-12670: Added validation in coders/mat.c to prevent an assertion
 failure in the function DestroyImage in MagickCore/image.c, which
 allowed attackers to cause a denial of service (bsc#1052731)
- CVE-2017-12667: Fixed a memory leak vulnerability in the function
 ReadMATImage in coders/mat.c (bsc#1052732)
- CVE-2017-13146: Fixed a memory leak vulnerability in the function
 ReadMATImage in coders/mat.c (bsc#1055323)
- CVE-2017-10800: Processing MATLAB images in coders/mat.c could have lead
 to a denial of service (OOM) in ReadMATImage() if the size specified for
 a MAT Object was larger than the actual amount of data (bsc#1047044)
- CVE-2017-13648: Fixed a memory leak vulnerability in the function
 ReadMATImage in coders/mat.c (bsc#1055434)
- CVE-2017-11141: Fixed a memory leak vulnerability in the function
 ReadMATImage in coders\mat.c that could have caused memory exhaustion
 via a crafted MAT file, related to incorrect ordering of a
 SetImageExtent call (bsc#1047898)
- CVE-2017-11529: The ReadMATImage function in coders/mat.c allowed remote
 attackers to cause a denial of service (memory leak) via a crafted file
 (bsc#1050120)
- CVE-2017-12564: Fixed a memory leak vulnerability in the function
 ReadMATImage in coders/mat.c, which allowed attackers to cause a denial
 of service (bsc#1052468)
- CVE-2017-12434: Added a missing NULL check in the function ReadMATImage
 in coders/mat.c, which allowed attackers to cause a denial of service
 (assertion failure) in DestroyImageInfo in image.c (bsc#1052550)
- CVE-2017-12675: Added a missing check for multidimensional data
 coders/mat.c, that could have lead to a memory leak in the function
 ReadImage in MagickCore/constitute.c, which allowed attackers to cause a
 denial of service (bsc#1052710)
- CVE-2017-14326: Fixed a memory leak vulnerability in the function
 ReadMATImage in coders/mat.c, which allowed attackers to cause a denial
 of service via a crafted file (bsc#1058640)
- CVE-2017-11644: Processesing a crafted ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on SUSE Linux Enterprise Workstation Extension 12-SP3, SUSE Linux Enterprise Workstation Extension 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Desktop 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-debuginfo", rpm:"ImageMagick-debuginfo~6.8.8.1~71.26.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-debugsource", rpm:"ImageMagick-debugsource~6.8.8.1~71.26.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.26.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1-debuginfo", rpm:"libMagickCore-6_Q16-1-debuginfo~6.8.8.1~71.26.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.26.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1-debuginfo", rpm:"libMagickWand-6_Q16-1-debuginfo~6.8.8.1~71.26.1", rls:"SLES12.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-debuginfo", rpm:"ImageMagick-debuginfo~6.8.8.1~71.26.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-debugsource", rpm:"ImageMagick-debugsource~6.8.8.1~71.26.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.26.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1-debuginfo", rpm:"libMagickCore-6_Q16-1-debuginfo~6.8.8.1~71.26.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.26.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1-debuginfo", rpm:"libMagickWand-6_Q16-1-debuginfo~6.8.8.1~71.26.1", rls:"SLES12.0SP2"))) {
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
