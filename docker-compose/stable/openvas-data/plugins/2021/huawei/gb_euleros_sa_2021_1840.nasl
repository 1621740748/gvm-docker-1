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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1840");
  script_version("2021-05-03T06:23:09+0000");
  script_cve_id("CVE-2020-10177", "CVE-2020-10378", "CVE-2020-35653", "CVE-2021-25290");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-05-03 06:23:09 +0000 (Mon, 03 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-03 06:23:09 +0000 (Mon, 03 May 2021)");
  script_name("Huawei EulerOS: Security Advisory for python-pillow (EulerOS-SA-2021-1840)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1840");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1840");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'python-pillow' package(s) announced via the EulerOS-SA-2021-1840 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in Pillow before 8.1.1. In TiffDecode.c, there is a negative-offset memcpy with an invalid size.(CVE-2021-25290)

In libImaging/PcxDecode.c in Pillow before 7.1.0, an out-of-bounds read can occur when reading PCX files where state-shuffle is instructed to read beyond state-buffer.(CVE-2020-10378)

In Pillow before 8.1.0, PcxDecode has a buffer over-read when decoding a crafted PCX file because the user-supplied stride value is trusted for buffer calculations.(CVE-2020-35653)

Pillow before 7.1.0 has multiple out-of-bounds reads in libImaging/FliDecode.c.(CVE-2020-10177)");

  script_tag(name:"affected", value:"'python-pillow' package(s) on Huawei EulerOS V2.0SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-pillow", rpm:"python-pillow~2.0.0~19.gitd1c6db8.h6", rls:"EULEROS-2.0SP3"))) {
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