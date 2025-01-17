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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1480");
  script_version("2021-03-05T07:08:12+0000");
  script_cve_id("CVE-2020-28366", "CVE-2020-28367", "CVE-2020-29509", "CVE-2020-29510", "CVE-2020-29511");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-03-05 07:08:12 +0000 (Fri, 05 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-05 07:08:12 +0000 (Fri, 05 Mar 2021)");
  script_name("Huawei EulerOS: Security Advisory for golang (EulerOS-SA-2021-1480)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.6\.6");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1480");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1480");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'golang' package(s) announced via the EulerOS-SA-2021-1480 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Go before 1.14.12 and 1.15.x before 1.15.5 allows Code Injection.

(CVE-2020-28366)

Go before 1.14.12 and 1.15.x before 1.15.5 allows Argument Injection.(CVE-2020-28367)

The encoding/xml package in Go (all versions) does not correctly preserve the semantics of attribute namespace prefixes during tokenization round-trips, which allows an attacker to craft inputs that behave in conflicting ways during different stages of processing in affected downstream applications.(CVE-2020-29509)

The encoding/xml package in Go (all versions) does not correctly preserve the semantics of attribute namespace prefixes during tokenization round-trips, which allows an attacker to craft inputs that behave in conflicting ways during different stages of processing in affected downstream applications.(CVE-2020-29511)

The encoding/xml package in Go versions 1.15 and earlier does not correctly preserve the semantics of directives during tokenization round-trips, which allows an attacker to craft inputs that behave in conflicting ways during different stages of processing in affected downstream applications.(CVE-2020-29510)");

  script_tag(name:"affected", value:"'golang' package(s) on Huawei EulerOS Virtualization 3.0.6.6.");

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

if(release == "EULEROSVIRT-3.0.6.6") {

  if(!isnull(res = isrpmvuln(pkg:"golang", rpm:"golang~1.13.3~9.h3.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-bin", rpm:"golang-bin~1.13.3~9.h3.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-src", rpm:"golang-src~1.13.3~9.h3.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
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