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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1481");
  script_version("2021-03-05T07:08:21+0000");
  script_cve_id("CVE-2020-12658");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-03-05 07:08:21 +0000 (Fri, 05 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-05 07:08:21 +0000 (Fri, 05 Mar 2021)");
  script_name("Huawei EulerOS: Security Advisory for gssproxy (EulerOS-SA-2021-1481)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.6\.6");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1481");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1481");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'gssproxy' package(s) announced via the EulerOS-SA-2021-1481 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"** DISPUTED ** gssproxy (aka gss-proxy) before 0.8.3 does not unlock cond_mutex before pthread exit in gp_worker_main() in gp_workers.c. NOTE: An upstream comment states 'We are already on a shutdown path when running the code in question, so a DoS there doesn't make any sense, and there has been no additional information provided us (as upstream) to indicate why this would be a problem.'(CVE-2020-12658)");

  script_tag(name:"affected", value:"'gssproxy' package(s) on Huawei EulerOS Virtualization 3.0.6.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"gssproxy", rpm:"gssproxy~0.7.0~17.h2.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
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