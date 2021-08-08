# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2018.1125");
  script_version("2021-07-13T10:05:59+0000");
  script_cve_id("CVE-2018-5148", "CVE-2018-5150", "CVE-2018-5154", "CVE-2018-5155", "CVE-2018-5157", "CVE-2018-5158", "CVE-2018-5159", "CVE-2018-5168", "CVE-2018-5178", "CVE-2018-5183");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-13 10:05:59 +0000 (Tue, 13 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-01-23 11:13:36 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for firefox (EulerOS-SA-2018-1125)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2018-1125");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1125");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'firefox' package(s) announced via the EulerOS-SA-2018-1125 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Use-after-free in compositor potentially allows code execution (CVE-2018-5148)

Memory safety bugs fixed in Firefox 60 and Firefox ESR 52.8 (CVE-2018-5150)

Backport critical security fixes in Skia (CVE-2018-5183)

Use-after-free with SVG animations and clip paths (CVE-2018-5154)

Use-after-free with SVG animations and text paths (CVE-2018-5155)

Same-origin bypass of PDF Viewer to view protected PDF files (CVE-2018-5157)

Malicious PDF can inject JavaScript into PDF Viewer (CVE-2018-5158)

Integer overflow and out-of-bounds write in Skia (CVE-2018-5159)

Lightweight themes can be installed without user interaction (CVE-2018-5168)

Buffer overflow during UTF-8 to Unicode string conversion through legacy extension (CVE-2018-5178)");

  script_tag(name:"affected", value:"'firefox' package(s) on Huawei EulerOS V2.0SP1.");

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

if(release == "EULEROS-2.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~52.8.0~1.h1", rls:"EULEROS-2.0SP1"))) {
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
