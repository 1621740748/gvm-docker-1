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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.2411");
  script_version("2021-08-02T11:01:01+0000");
  script_cve_id("CVE-2020-0431", "CVE-2020-0432", "CVE-2020-12351", "CVE-2020-12352", "CVE-2020-24490", "CVE-2020-25641", "CVE-2020-25643", "CVE-2020-25645", "CVE-2020-26088");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"2021-08-02 11:01:01 +0000 (Mon, 02 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-03 13:15:00 +0000 (Tue, 03 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-04 08:56:16 +0000 (Wed, 04 Nov 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2020-2411)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP9");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-2411");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2411");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2020-2411 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In kbd_keycode of keyboard.c, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-144161459(CVE-2020-0431)

A flaw was found in the HDLC_PPP module of the Linux kernel in versions before 5.9-rc7. Memory corruption and a read overflow is caused by improper input validation in the ppp_cp_parse_cr function which can cause the system to crash or cause a denial of service. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.(CVE-2020-25643)

A flaw was found in the Linux kernel in versions before 5.9-rc7. Traffic between two Geneve endpoints may be unencrypted when IPsec is configured to encrypt traffic for the specific UDP port used by the GENEVE tunnel allowing anyone between the two endpoints to read the traffic unencrypted. The main threat from this vulnerability is to data confidentiality.(CVE-2020-25645)

An information leak flaw was found in the way the Linux kernel's Bluetooth stack implementation handled initialization of stack memory when handling certain AMP packets. A remote attacker in adjacent range could use this flaw to leak small portions of stack memory on the system by sending a specially crafted AMP packets. The highest threat from this vulnerability is to data confidentiality.(CVE-2020-12352)

A flaw was found in the way the Linux kernel Bluetooth implementation handled L2CAP packets with A2MP CID. A remote attacker in adjacent range could use this flaw to crash the system causing denial of service or potentially execute arbitrary code on the system by sending a specially crafted L2CAP packet. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.(CVE-2020-12351)

A heap buffer overflow flaw was found in the way the Linux kernels Bluetooth implementation processed extended advertising report events. This flaw allows a remote attacker in an adjacent range to crash the system, causing a denial of service or to potentially execute arbitrary code on the system by sending a specially crafted Bluetooth packet. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.(CVE-2020-24490))

A missing CAP_NET_RAW check in NFC socket creation in net/nfc/rawsock.c in the Linux kernel before 5.8.2 could be used by local attackers to create raw sockets, bypassing security mechanisms, aka CID-26896f01467a.( ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP9.");

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

if(release == "EULEROS-2.0SP9") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.90~vhulk2009.2.0.h284.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.90~vhulk2009.2.0.h284.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.90~vhulk2009.2.0.h284.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.90~vhulk2009.2.0.h284.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
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
