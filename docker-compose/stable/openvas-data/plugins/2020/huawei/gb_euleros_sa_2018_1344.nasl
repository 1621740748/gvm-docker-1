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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2018.1344");
  script_version("2021-07-13T10:05:59+0000");
  script_cve_id("CVE-2014-9402", "CVE-2016-3075", "CVE-2018-11236");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-07-13 10:05:59 +0000 (Tue, 13 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-01-23 11:22:33 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for glibc (EulerOS-SA-2018-1344)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-2\.5\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2018-1344");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1344");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'glibc' package(s) announced via the EulerOS-SA-2018-1344 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The nss_dns implementation of getnetbyname in GNU C Library (aka glibc) before 2.21, when the DNS backend in the Name Service Switch configuration is enabled, allows remote attackers to cause a denial of service (infinite loop) by sending a positive answer while a network name is being process.(CVE-2014-9402)

A stack overflow vulnerability was found in _nss_dns_getnetbyname_r.On systems with nsswitch configured to include 'networks: dns' with a privileged or network-facing service that would attempt to resolve user-provided network names, an attacker could provide an excessively long network name, resulting in stack corruption and code execution.(CVE-2016-3075)

stdlib/canonicalize.c in the GNU C Library (aka glibc or libc6) 2.27 and earlier, when processing very long pathname arguments to the realpath function, could encounter an integer overflow on 32-bit architectures, leading to a stack-based buffer overflow and, potentially, arbitrary code execution.(CVE-2018-11236)");

  script_tag(name:"affected", value:"'glibc' package(s) on Huawei EulerOS Virtualization 2.5.0.");

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

if(release == "EULEROSVIRT-2.5.0") {

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.17~111.h12", rls:"EULEROSVIRT-2.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.17~111.h12", rls:"EULEROSVIRT-2.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.17~111.h12", rls:"EULEROSVIRT-2.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.17~111.h12", rls:"EULEROSVIRT-2.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.17~111.h12", rls:"EULEROSVIRT-2.5.0"))) {
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
