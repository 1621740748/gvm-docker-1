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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2477");
  script_version("2021-07-13T10:05:59+0000");
  script_cve_id("CVE-2017-10965", "CVE-2017-10966", "CVE-2017-5193", "CVE-2017-5194", "CVE-2017-5356", "CVE-2017-9468", "CVE-2017-9469", "CVE-2018-5205", "CVE-2018-5206", "CVE-2018-5207", "CVE-2018-5208");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-13 10:05:59 +0000 (Tue, 13 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-01-23 13:00:43 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for irssi (EulerOS-SA-2019-2477)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2477");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2477");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'irssi' package(s) announced via the EulerOS-SA-2019-2477 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Irssi before 1.0.6, a calculation error in the completion code could cause a heap buffer overflow when completing certain strings.(CVE-2018-5208)

When using incomplete escape codes, Irssi before 1.0.6 may access data beyond the end of the string.(CVE-2018-5205)

When the channel topic is set without specifying a sender, Irssi before 1.0.6 may dereference a NULL pointer.(CVE-2018-5206)

When using an incomplete variable argument, Irssi before 1.0.6 may access data beyond the end of the string.(CVE-2018-5207)

The nickcmp function in Irssi before 0.8.21 allows remote attackers to cause a denial of service (NULL pointer dereference and crash) via a message without a nick.(CVE-2017-5193)

Use-after-free vulnerability in Irssi before 0.8.21 allows remote attackers to cause a denial of service (crash) via an invalid nick message.(CVE-2017-5194)

Irssi before 0.8.21 allows remote attackers to cause a denial of service (out-of-bounds read and crash) via a string containing a formatting sequence (%[) without a closing bracket (]).(CVE-2017-5356)

In Irssi before 1.0.3, when receiving a DCC message without source nick/host, it attempts to dereference a NULL pointer. Thus, remote IRC servers can cause a crash.(CVE-2017-9468)

In Irssi before 1.0.3, when receiving certain incorrectly quoted DCC files, it tries to find the terminating quote one byte before the allocated memory. Thus, remote attackers might be able to cause a crash.(CVE-2017-9469)

An issue was discovered in Irssi before 1.0.4. When receiving messages with invalid time stamps, Irssi would try to dereference a NULL pointer.(CVE-2017-10965)

An issue was discovered in Irssi before 1.0.4. While updating the internal nick list, Irssi could incorrectly use the GHashTable interface and free the nick while updating it. This would then result in use-after-free conditions on each access of the hash table.(CVE-2017-10966)");

  script_tag(name:"affected", value:"'irssi' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"irssi", rpm:"irssi~0.8.15~16.h6", rls:"EULEROS-2.0SP2"))) {
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
