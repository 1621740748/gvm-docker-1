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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1225");
  script_version("2021-02-05T15:25:36+0000");
  script_cve_id("CVE-2017-14927", "CVE-2017-9083", "CVE-2017-9406", "CVE-2017-9408", "CVE-2017-9865");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-02-05 15:25:36 +0000 (Fri, 05 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-05 15:04:16 +0000 (Fri, 05 Feb 2021)");
  script_name("Huawei EulerOS: Security Advisory for poppler (EulerOS-SA-2021-1225)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1225");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1225");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'poppler' package(s) announced via the EulerOS-SA-2021-1225 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Poppler 0.54.0, a memory leak vulnerability was found in the function gmalloc in gmem.cc, which allows attackers to cause a denial of service via a crafted file.(CVE-2017-9406)

In Poppler 0.54.0, a memory leak vulnerability was found in the function Object::initArray in Object.cc, which allows attackers to cause a denial of service via a crafted file.(CVE-2017-9408)

The function GfxImageColorMap::getGray in GfxState.cc in Poppler 0.54.0 allows remote attackers to cause a denial of service (stack-based buffer over-read and application crash) via a crafted PDF document, related to missing color-map validation in ImageOutputDev.cc.(CVE-2017-9865)

In Poppler 0.59.0, a NULL Pointer Dereference exists in the SplashOutputDev::type3D0() function in SplashOutputDev.cc via a crafted PDF document.(CVE-2017-14927)

poppler 0.54.0, as used in Evince and other products, has a NULL pointer dereference in the JPXStream::readUByte function in JPXStream.cc. For example, the perf_test utility will crash (segmentation fault) when parsing an invalid PDF file.(CVE-2017-9083)");

  script_tag(name:"affected", value:"'poppler' package(s) on Huawei EulerOS V2.0SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"poppler", rpm:"poppler~0.26.5~17.h26.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-glib", rpm:"poppler-glib~0.26.5~17.h26.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-qt", rpm:"poppler-qt~0.26.5~17.h26.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-utils", rpm:"poppler-utils~0.26.5~17.h26.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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