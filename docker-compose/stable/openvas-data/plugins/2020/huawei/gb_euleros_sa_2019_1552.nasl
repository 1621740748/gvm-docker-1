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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1552");
  script_version("2021-07-13T10:05:59+0000");
  script_cve_id("CVE-2012-4412", "CVE-2013-1914", "CVE-2013-4237", "CVE-2013-4788", "CVE-2013-7423", "CVE-2014-0475", "CVE-2014-6040", "CVE-2014-9402", "CVE-2014-9761", "CVE-2015-1472", "CVE-2015-1781", "CVE-2015-5277", "CVE-2015-8776", "CVE-2016-3075", "CVE-2017-15670", "CVE-2019-9169");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-07-13 10:05:59 +0000 (Tue, 13 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-01-23 12:12:58 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for glibc (EulerOS-SA-2019-1552)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1552");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1552");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'glibc' package(s) announced via the EulerOS-SA-2019-1552 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the nss_files backend for the Name Service Switch in glibc would return incorrect data to applications or corrupt the heap (depending on adjacent heap contents). A local attacker could potentially use this flaw to execute arbitrary code on the system.(CVE-2015-5277)

A directory traversal flaw was found in the way glibc loaded locale files. An attacker able to make an application use a specially crafted locale name value (for example, specified in an LC_* environment variable) could possibly use this flaw to execute arbitrary code with the privileges of that application.(CVE-2014-0475)

It was found that out-of-range time values passed to the strftime() function could result in an out-of-bounds memory access. This could lead to application crash or, potentially, information disclosure.(CVE-2015-8776)

The GNU C Library (aka glibc or libc6) before 2.27 contains an off-by-one error leading to a heap-based buffer overflow in the glob function in glob.c, related to the processing of home directories using the ~ operator followed by a long string.(CVE-2017-15670)

The PTR_MANGLE implementation in the GNU C Library (aka glibc or libc6) 2.4, 2.17, and earlier, and Embedded GLIBC (EGLIBC) does not initialize the random value for the pointer guard, which makes it easier for context-dependent attackers to control execution flow by leveraging a buffer-overflow vulnerability in an application and using the known zero value pointer guard to calculate a pointer address.(CVE-2013-4788)

An out-of-bounds read flaw was found in the way glibc's iconv() function converted certain encoded data to UTF-8. An attacker able to make an application call the iconv() function with a specially crafted argument could use this flaw to crash that application.(CVE-2014-6040)

A stack overflow vulnerability was found in _nss_dns_getnetbyname_r. On systems with nsswitch configured to include ''networks: dns'' with a privileged or network-facing service that would attempt to resolve user-provided network names, an attacker could provide an excessively long network name, resulting in stack corruption and code execution.(CVE-2016-3075)

Integer overflow in string/strcoll_l.c in the GNU C Library (aka glibc or libc6) 2.17 and earlier allows context-dependent attackers to cause a denial of service (crash) or possibly execute arbitrary code via a long string, which triggers a heap-based buffer overflow.(CVE-2012-4412)

A heap-based buffer overflow flaw was found in glibc's swscanf() function. An attacker able to make an application call the swscanf() function could use this flaw to crash that ap ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'glibc' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.17~222.h11", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.17~222.h11", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.17~222.h11", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.17~222.h11", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.17~222.h11", rls:"EULEROSVIRT-3.0.1.0"))) {
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
