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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1637");
  script_version("2021-07-13T10:05:59+0000");
  script_cve_id("CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-07-13 10:05:59 +0000 (Tue, 13 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-01-23 12:18:22 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1637)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-2\.5\.2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1637");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1637");
  script_xref(name:"URL", value:"http://developer.huawei.com/ict/en/performance_update");
  script_xref(name:"URL", value:"https://developer.huawei.com/ict/en/site-euleros/article/switch");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-1637 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The recent speculative execution CVEs address three potential attacks across a wide variety of architectures and hardware platforms.

Note: This issue is present in hardware and cannot be fully fixed via software update. The nature of these vulnerabilities and their fixes introduces the possibility of reduced performance on patched systems. The performance impact depends on the hardware and the applications in place.

The first two variants abuse speculative execution to perform bounds-check bypass (CVE-2017-5753), or by utilizing branch target injection (CVE-2017-5715) to cause kernel code at an address under attacker control to execute speculatively. Collectively these are known as 'Spectre'.

Variant CVE-2017-5715 fixes require CPU microcode to update.And advise to contact hardware vendors to receive the appropriate microcode for your processor.

The third variant (CVE-2017-5754) relies on the fact that, on impacted microprocessors, during speculative execution of instruction permission faults, exception generation triggered by a faulting access is suppressed until the retirement of the whole instruction block. Researchers have called this exploit 'Meltdown'.

Note1: Upgrade and performance specifications, please see [link moved to references]

Note2: Description of microcode and security patches switches, please see [link moved to references]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization 2.5.2.");

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

if(release == "EULEROSVIRT-2.5.2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~514.35.4.1_39", rls:"EULEROSVIRT-2.5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~514.35.4.1_39", rls:"EULEROSVIRT-2.5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~514.35.4.1_39", rls:"EULEROSVIRT-2.5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~514.35.4.1_39", rls:"EULEROSVIRT-2.5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~514.35.4.1_39", rls:"EULEROSVIRT-2.5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~514.35.4.1_39", rls:"EULEROSVIRT-2.5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~514.35.4.1_39", rls:"EULEROSVIRT-2.5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~514.35.4.1_39", rls:"EULEROSVIRT-2.5.2"))) {
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
