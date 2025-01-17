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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1082");
  script_version("2021-07-13T10:05:59+0000");
  script_cve_id("CVE-2019-15161", "CVE-2019-15162", "CVE-2019-15163", "CVE-2019-15164", "CVE-2019-15165");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-07-13 10:05:59 +0000 (Tue, 13 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-01-23 13:19:51 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for libpcap (EulerOS-SA-2020-1082)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.5\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1082");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1082");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'libpcap' package(s) announced via the EulerOS-SA-2020-1082 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"sf-pcapng.c in libpcap before 1.9.1 does not properly validate the PHB header length before allocating memory.(CVE-2019-15165)

rpcapd/daemon.c in libpcap before 1.9.1 allows SSRF because a URL may be provided as a capture source.(CVE-2019-15164)

rpcapd/daemon.c in libpcap before 1.9.1 allows attackers to cause a denial of service (NULL pointer dereference and daemon crash) if a crypt() call fails.(CVE-2019-15163)

rpcapd/daemon.c in libpcap before 1.9.1 mishandles certain length values because of reuse of a variable. This may open up an attack vector involving extra data at the end of a request.(CVE-2019-15161)

rpcapd/daemon.c in libpcap before 1.9.1 on non-Windows platforms provides details about why authentication failed, which might make it easier for attackers to enumerate valid usernames.(CVE-2019-15162)");

  script_tag(name:"affected", value:"'libpcap' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.5.0.");

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

if(release == "EULEROSVIRTARM64-3.0.5.0") {

  if(!isnull(res = isrpmvuln(pkg:"libpcap", rpm:"libpcap~1.9.1~2.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.5.0"))) {
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
