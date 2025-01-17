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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1305");
  script_version("2021-02-22T08:22:03+0000");
  script_cve_id("CVE-2017-11533", "CVE-2017-13768", "CVE-2017-9501", "CVE-2019-14981", "CVE-2019-15140", "CVE-2019-16708", "CVE-2019-16709", "CVE-2019-16710", "CVE-2019-16711", "CVE-2019-19948", "CVE-2019-19949", "CVE-2020-13902", "CVE-2020-27766", "CVE-2020-29599");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-02-22 08:22:03 +0000 (Mon, 22 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-22 08:22:03 +0000 (Mon, 22 Feb 2021)");
  script_name("Huawei EulerOS: Security Advisory for ImageMagick (EulerOS-SA-2021-1305)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1305");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1305");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'ImageMagick' package(s) announced via the EulerOS-SA-2021-1305 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"coders/mat.c in ImageMagick 7.0.8-43 Q16 allows remote attackers to cause a denial of service (use-after-free and application crash) or possibly have unspecified other impact by crafting a Matlab image file that is mishandled in ReadImage in MagickCore/constitute.c.(CVE-2019-15140)

In ImageMagick 7.x before 7.0.8-41 and 6.x before 6.9.10-41, there is a divide-by-zero vulnerability in the MeanShiftImage function. It allows an attacker to cause a denial of service by sending a crafted file.(CVE-2019-14981)

ImageMagick 7.0.8-35 has a memory leak in magick/xwindow.c, related to XCreateImage.(CVE-2019-16708)

ImageMagick 7.0.8-35 has a memory leak in coders/dps.c, as demonstrated by XCreateImage.(CVE-2019-16709)

ImageMagick 7.0.8-35 has a memory leak in coders/dot.c, as demonstrated by AcquireMagickMemory in MagickCore/memory.c.(CVE-2019-16710)

ImageMagick 7.0.8-40 has a memory leak in Huffman2DEncodeImage in coders/ps2.c.(CVE-2019-16711)

In ImageMagick 7.0.8-43 Q16, there is a heap-based buffer overflow in the function WriteSGIImage of coders/sgi.c.(CVE-2019-19948)

In ImageMagick 7.0.8-43 Q16, there is a heap-based buffer over-read in the function WritePNGImage of coders/png.c, related to Magick_png_write_raw_profile and LocaleNCompare.(CVE-2019-19949)

ImageMagick 7.0.9-27 through 7.0.10-17 has a heap-based buffer over-read in BlobToStringInfo in MagickCore/string.c during TIFF image decoding.(CVE-2020-13902)

In ImageMagick 7.0.5-7 Q16, an assertion failure was found in the function LockSemaphoreInfo, which allows attackers to cause a denial of service via a crafted file.(CVE-2017-9501)

When ImageMagick 7.0.6-1 processes a crafted file in convert, it can lead to a heap-based buffer over-read in the WriteUILImage() function in coders/uil.c.(CVE-2017-11533)

Null Pointer Dereference in the IdentifyImage function in MagickCore/identify.c in ImageMagick through 7.0.6-10 allows an attacker to perform denial of service by sending a crafted image file.(CVE-2017-13768)

ImageMagick before 6.9.11-40 and 7.x before 7.0.10-40 mishandles the -authenticate option, which allows setting a password for password-protected PDF files. The user-controlled password was not properly escaped/sanitized and it was therefore possible to inject additional shell commands via coders/pdf.c.(CVE-2020-29599)

A flaw was found in ImageMagick in MagickCore/statistic.c. An attacker who submits a crafted file that is processed by ImageMagick could trigger undefined behavior in the form of values outside the range of type `unsigned long`. This would most likely lead to an impact to application availability, but could potentially cause other problems related to undefined behavior. This flaw affects ImageMagick versions prior to 7.0.8-69.(CVE-2020-27766)");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~6.9.9.38~1.h14", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-c++", rpm:"ImageMagick-c++~6.9.9.38~1.h14", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-libs", rpm:"ImageMagick-libs~6.9.9.38~1.h14", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-perl", rpm:"ImageMagick-perl~6.9.9.38~1.h14", rls:"EULEROS-2.0SP2"))) {
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