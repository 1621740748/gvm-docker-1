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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1207");
  script_version("2021-02-05T15:25:36+0000");
  script_cve_id("CVE-2016-9297", "CVE-2016-9448", "CVE-2017-11335", "CVE-2017-16232", "CVE-2017-9404");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-02-05 15:25:36 +0000 (Fri, 05 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-05 15:03:17 +0000 (Fri, 05 Feb 2021)");
  script_name("Huawei EulerOS: Security Advisory for libtiff (EulerOS-SA-2021-1207)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1207");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1207");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'libtiff' package(s) announced via the EulerOS-SA-2021-1207 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"There is a heap based buffer overflow in tools/tiff2pdf.c of LibTIFF 4.0.8 via a PlanarConfig=Contig image, which causes a more than one hundred bytes out-of-bounds write (related to the ZIPDecode function in tif_zip.c). A crafted input may lead to a remote denial of service attack or an arbitrary code execution attack.(CVE-2017-11335)

The TIFFFetchNormalTag function in LibTiff 4.0.6 allows remote attackers to cause a denial of service (out-of-bounds read) via crafted TIFF_SETGET_C16ASCII or TIFF_SETGET_C32_ASCII tag values.(CVE-2016-9297)

The TIFFFetchNormalTag function in LibTiff 4.0.6 allows remote attackers to cause a denial of service (NULL pointer dereference and crash) by setting the tags TIFF_SETGET_C16ASCII or TIFF_SETGET_C32_ASCII to values that access 0-byte arrays. NOTE: this vulnerability exists because of an incomplete fix for CVE-2016-9297.(CVE-2016-9448)

In LibTIFF 4.0.7, a memory leak vulnerability was found in the function OJPEGReadHeaderInfoSecTablesQTable in tif_ojpeg.c, which allows attackers to cause a denial of service via a crafted file.(CVE-2017-9404)

LibTIFF 4.0.8 has multiple memory leak vulnerabilities, which allow attackers to cause a denial of service (memory consumption), as demonstrated by tif_open.c, tif_lzw.c, and tif_aux.c. NOTE: Third parties were unable to reproduce the issue.(CVE-2017-16232)");

  script_tag(name:"affected", value:"'libtiff' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~4.0.3~27.h26.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.0.3~27.h26.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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