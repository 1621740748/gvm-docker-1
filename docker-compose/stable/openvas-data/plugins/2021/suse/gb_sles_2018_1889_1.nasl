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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1889.1");
  script_cve_id("CVE-2017-11613", "CVE-2017-18013", "CVE-2018-10963", "CVE-2018-7456", "CVE-2018-8905");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:43 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1889-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1889-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181889-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff' package(s) announced via the SUSE-SU-2018:1889-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tiff fixes the following security issues:
These security issues were fixed:
- CVE-2017-18013: Fixed a NULL pointer dereference in the
 tif_print.cTIFFPrintDirectory function that could have lead to denial of
 service (bsc#1074317).
- CVE-2018-10963: Fixed an assertion failure in the
 TIFFWriteDirectorySec() function in tif_dirwrite.c, which allowed remote
 attackers to cause a denial
 of service via a crafted file (bsc#1092949).
- CVE-2018-7456: Prevent a NULL Pointer dereference in the function
 TIFFPrintDirectory when using the tiffinfo tool to print crafted TIFF
 information, a different vulnerability than CVE-2017-18013 (bsc#1082825).
- CVE-2017-11613: Prevent denial of service in the TIFFOpen function.
 During the TIFFOpen process, td_imagelength is not checked. The value of
 td_imagelength can be directly controlled by an input file. In the
 ChopUpSingleUncompressedStrip function, the _TIFFCheckMalloc function is
 called based on td_imagelength. If the value of td_imagelength is set
 close to the amount of system memory, it will hang the system or trigger
 the OOM killer (bsc#1082332).
- CVE-2018-8905: Prevent heap-based buffer overflow in the function
 LZWDecodeCompat via a crafted TIFF file (bsc#1086408).");

  script_tag(name:"affected", value:"'tiff' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15, SUSE Linux Enterprise Module for Basesystem 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-32bit", rpm:"libtiff5-32bit~4.0.9~5.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-32bit-debuginfo", rpm:"libtiff5-32bit-debuginfo~4.0.9~5.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff-debugsource", rpm:"tiff-debugsource~4.0.9~5.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.0.9~5.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.0.9~5.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-debuginfo", rpm:"libtiff5-debuginfo~4.0.9~5.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff-debuginfo", rpm:"tiff-debuginfo~4.0.9~5.9.1", rls:"SLES15.0"))) {
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
