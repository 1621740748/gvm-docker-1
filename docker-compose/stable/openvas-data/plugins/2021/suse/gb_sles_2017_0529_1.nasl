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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0529.1");
  script_cve_id("CVE-2016-10046", "CVE-2016-10048", "CVE-2016-10049", "CVE-2016-10050", "CVE-2016-10051", "CVE-2016-10052", "CVE-2016-10059", "CVE-2016-10060", "CVE-2016-10061", "CVE-2016-10062", "CVE-2016-10063", "CVE-2016-10064", "CVE-2016-10065", "CVE-2016-10068", "CVE-2016-10069", "CVE-2016-10070", "CVE-2016-10071", "CVE-2016-10144", "CVE-2016-10145", "CVE-2016-10146", "CVE-2016-9773", "CVE-2017-5506", "CVE-2017-5507", "CVE-2017-5508", "CVE-2017-5510", "CVE-2017-5511");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0529-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0529-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170529-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2017:0529-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:
- CVE-2016-10046: Prevent buffer overflow in draw.c caused by an incorrect
 length calculation (bsc#1017308)
- CVE-2016-10048: Arbitrary module could have been load because relative
 path were not escaped (bsc#1017310)
- CVE-2016-10049: Corrupt RLE files could have overflowed a buffer due to
 a incorrect length calculation (bsc#1017311)
- CVE-2016-10050: Corrupt RLE files could have overflowed a heap buffer
 due to a missing offset check (bsc#1017312)
- CVE-2016-10051: Fixed use after free when reading PWP files (bsc#1017313)
- CVE-2016-10052: Added bound check to exif parsing of JPEG files
 (bsc#1017314)
- CVE-2016-10059: Unchecked calculation when reading TIFF files could have
 lead to a buffer overflow (bsc#1017318)
- CVE-2016-10060: Improved error handling when writing files to not mask
 errors (bsc#1017319)
- CVE-2016-10061: Improved error handling when writing files to not mask
 errors (bsc#1017319).
- CVE-2016-10062: Improved error handling when writing files to not mask
 errors (bsc#1017319).
- CVE-2016-10063: Check validity of extend during TIFF file reading
 (bsc#1017320)
- CVE-2016-10064: Improved checks for buffer overflow when reading TIFF
 files (bsc#1017321)
- CVE-2016-10065: Unchecked calculations when reading VIFF files could
 have lead to out of bound reads (bsc#1017322)
- CVE-2016-10068: Prevent NULL pointer access when using the MSL
 interpreter (bsc#1017324)
- CVE-2016-10069: Add check for invalid mat file (bsc#1017325).
- CVE-2016-10070: Prevent allocating the wrong amount of memory when
 reading mat files (bsc#1017326)
- CVE-2016-10071: Prevent allocating the wrong amount of memory when
 reading mat files (bsc#1017326)
- CVE-2016-10144: Added a check after allocating memory when parsing IPL
 files (bsc#1020433)
- CVE-2016-10145: Fixed of-by-one in string copy operation when parsing
 WPG files (bsc#1020435)
- CVE-2016-10146: Captions and labels were handled incorrectly, causing a
 memory leak that could have lead to DoS (bsc#1020443)
- CVE-2017-5506: Missing offset check leading to a double-free
 (bsc#1020436)
- CVE-2017-5507: Fixed a memory leak when reading MPC files allowing for
 DoS (bsc#1020439)
- CVE-2017-5508: Increase the amount of memory allocated for TIFF pixels
 to prevent a heap buffer-overflow (bsc#1020441)
- CVE-2017-5510: Prevent out-of-bounds write when reading PSD files
 (bsc#1020446).
- CVE-2017-5511: A missing cast when reading PSD files could have caused
 memory corruption by a heap overflow (bsc#1020448)
This update removes the fix for CVE-2016-9773. ImageMagick-6 was not affected by CVE-2016-9773 and it caused a regression (at least in GraphicsMagick) (bsc#1017421).");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on SUSE Linux Enterprise Workstation Extension 12-SP2, SUSE Linux Enterprise Workstation Extension 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP1, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP1.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-debuginfo", rpm:"ImageMagick-debuginfo~6.8.8.1~59.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-debugsource", rpm:"ImageMagick-debugsource~6.8.8.1~59.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~59.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1-debuginfo", rpm:"libMagickCore-6_Q16-1-debuginfo~6.8.8.1~59.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~59.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1-debuginfo", rpm:"libMagickWand-6_Q16-1-debuginfo~6.8.8.1~59.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-debuginfo", rpm:"ImageMagick-debuginfo~6.8.8.1~59.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-debugsource", rpm:"ImageMagick-debugsource~6.8.8.1~59.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~59.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1-debuginfo", rpm:"libMagickCore-6_Q16-1-debuginfo~6.8.8.1~59.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~59.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1-debuginfo", rpm:"libMagickWand-6_Q16-1-debuginfo~6.8.8.1~59.1", rls:"SLES12.0SP1"))) {
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
