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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0349.1");
  script_cve_id("CVE-2017-10995", "CVE-2017-11505", "CVE-2017-11525", "CVE-2017-11526", "CVE-2017-11539", "CVE-2017-11639", "CVE-2017-11750", "CVE-2017-12565", "CVE-2017-12640", "CVE-2017-12641", "CVE-2017-12643", "CVE-2017-12671", "CVE-2017-12673", "CVE-2017-12676", "CVE-2017-12935", "CVE-2017-13059", "CVE-2017-13141", "CVE-2017-13142", "CVE-2017-13147", "CVE-2017-14103", "CVE-2017-14649", "CVE-2017-15218", "CVE-2017-17504", "CVE-2017-17681", "CVE-2017-17879", "CVE-2017-17884", "CVE-2017-17914", "CVE-2017-18008", "CVE-2017-18027", "CVE-2017-18029", "CVE-2017-9261", "CVE-2017-9262", "CVE-2018-5246", "CVE-2018-5685");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-14 18:16:00 +0000 (Wed, 14 Oct 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0349-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0349-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180349-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2018:0349-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes several issues.
These security issues were fixed:
- CVE-2017-18027: Prevent memory leak vulnerability in the function
 ReadMATImage which allowed remote attackers to cause a denial of service
 via a crafted file (bsc#1076051)
- CVE-2017-18029: Prevent memory leak in the function ReadMATImage which
 allowed remote attackers to cause a denial of service via a crafted file
 (bsc#1076021)
- CVE-2017-17681: Prevent infinite loop in the function ReadPSDChannelZip
 in coders/psd.c, which allowed attackers to cause a denial of service
 (CPU exhaustion) via a crafted psd image file (bsc#1072901).
- CVE-2017-18008: Prevent memory Leak in ReadPWPImage which allowed
 attackers to cause a denial of service via a PWP file (bsc#1074309).
- CVE-2018-5685: Prevent infinite loop and application hang in the
 ReadBMPImage function. Remote attackers could leverage this
 vulnerability to cause a denial
 of service via an image file with a crafted bit-field mask value
 (bsc#1075939)
- CVE-2017-11639: Prevent heap-based buffer over-read in the
 WriteCIPImage() function, related to the GetPixelLuma function in
 MagickCore/pixel-accessor.h (bsc#1050635)
- CVE-2017-11525: Prevent memory consumption in the ReadCINImage function
 that allowed remote attackers to cause a denial of service (bsc#1050098)
- CVE-2017-9262: The ReadJNGImage function in coders/png.c allowed
 attackers to cause a denial of service (memory leak) via a crafted file
 (bsc#1043353).
- CVE-2017-9261: The ReadMNGImage function in coders/png.c allowed
 attackers to cause a denial of service (memory leak) via a crafted file
 (bsc#1043354).
- CVE-2017-10995: The mng_get_long function in coders/png.c allowed remote
 attackers to cause a denial of service (heap-based buffer over-read and
 application crash) via a crafted MNG image (bsc#1047908).
- CVE-2017-11539: Prevent memory leak in the ReadOnePNGImage() function in
 coders/png.c (bsc#1050037).
- CVE-2017-11505: The ReadOneJNGImage function in coders/png.c allowed
 remote attackers to cause a denial of service (large loop and CPU
 consumption) via a crafted file (bsc#1050072).
- CVE-2017-11526: The ReadOneMNGImage function in coders/png.c allowed
 remote attackers to cause a denial of service (large loop and CPU
 consumption) via a crafted file (bsc#1050100).
- CVE-2017-11750: The ReadOneJNGImage function in coders/png.c allowed
 remote attackers to cause a denial of service (NULL pointer dereference)
 via a crafted file (bsc#1051442).
- CVE-2017-12565: Prevent memory leak in the function ReadOneJNGImage in
 coders/png.c, which allowed attackers to cause a denial of service
 (bsc#1052470).
- CVE-2017-12676: Prevent memory leak in the function ReadOneJNGImage in
 coders/png.c, which allowed attackers to cause a denial of service
 (bsc#1052708).
- CVE-2017-12673: Prevent memory leak in the function ReadOneMNGImage in
 coders/png.c, which allowed ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-debuginfo", rpm:"ImageMagick-debuginfo~6.8.8.1~71.33.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-debugsource", rpm:"ImageMagick-debugsource~6.8.8.1~71.33.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.33.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1-debuginfo", rpm:"libMagickCore-6_Q16-1-debuginfo~6.8.8.1~71.33.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.33.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1-debuginfo", rpm:"libMagickWand-6_Q16-1-debuginfo~6.8.8.1~71.33.1", rls:"SLES12.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-debuginfo", rpm:"ImageMagick-debuginfo~6.8.8.1~71.33.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-debugsource", rpm:"ImageMagick-debugsource~6.8.8.1~71.33.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.33.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1-debuginfo", rpm:"libMagickCore-6_Q16-1-debuginfo~6.8.8.1~71.33.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.33.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1-debuginfo", rpm:"libMagickWand-6_Q16-1-debuginfo~6.8.8.1~71.33.1", rls:"SLES12.0SP2"))) {
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
