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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1778");
  script_version("2021-05-03T06:19:55+0000");
  script_cve_id("CVE-2019-1010006", "CVE-2019-11459");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-05-03 06:19:55 +0000 (Mon, 03 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-03 06:19:55 +0000 (Mon, 03 May 2021)");
  script_name("Huawei EulerOS: Security Advisory for evince (EulerOS-SA-2021-1778)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1778");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1778");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'evince' package(s) announced via the EulerOS-SA-2021-1778 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Evince 3.26.0 is affected by buffer overflow. The impact is: DOS / Possible code execution. The component is: backend/tiff/tiff-document.c. The attack vector is: Victim must open a crafted PDF file. The issue occurs because of an incorrect integer overflow protection mechanism in tiff_document_render and tiff_document_get_thumbnail.(CVE-2019-1010006)

The tiff_document_render() and tiff_document_get_thumbnail() functions in the TIFF document backend in GNOME Evince through 3.32.0 did not handle errors from TIFFReadRGBAImageOriented(), leading to uninitialized memory use when processing certain TIFF image files.(CVE-2019-11459)");

  script_tag(name:"affected", value:"'evince' package(s) on Huawei EulerOS V2.0SP3.");

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

if(release == "EULEROS-2.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"evince", rpm:"evince~3.14.2~5.h4", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-dvi", rpm:"evince-dvi~3.14.2~5.h4", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-libs", rpm:"evince-libs~3.14.2~5.h4", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-nautilus", rpm:"evince-nautilus~3.14.2~5.h4", rls:"EULEROS-2.0SP3"))) {
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