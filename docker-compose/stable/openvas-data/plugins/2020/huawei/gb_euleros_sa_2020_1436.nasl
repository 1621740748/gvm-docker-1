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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1436");
  script_version("2021-07-28T11:00:55+0000");
  script_cve_id("CVE-2016-7795");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-07-28 11:00:55 +0000 (Wed, 28 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-28 01:29:00 +0000 (Fri, 28 Jul 2017)");
  script_tag(name:"creation_date", value:"2020-04-16 05:52:58 +0000 (Thu, 16 Apr 2020)");
  script_name("Huawei EulerOS: Security Advisory for systemd (EulerOS-SA-2020-1436)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1436");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1436");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'systemd' package(s) announced via the EulerOS-SA-2020-1436 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The manager_invoke_notify_message function in systemd 231 and earlier allows local users to cause a denial of service (assertion failure and PID 1 hang) via a zero-length message received over a notify socket.(CVE-2016-7795)");

  script_tag(name:"affected", value:"'systemd' package(s) on Huawei EulerOS V2.0SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libgudev1", rpm:"libgudev1~219~30.6.h73", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgudev1-devel", rpm:"libgudev1-devel~219~30.6.h73", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~219~30.6.h73", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-devel", rpm:"systemd-devel~219~30.6.h73", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-libs", rpm:"systemd-libs~219~30.6.h73", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-python", rpm:"systemd-python~219~30.6.h73", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysv", rpm:"systemd-sysv~219~30.6.h73", rls:"EULEROS-2.0SP3"))) {
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
