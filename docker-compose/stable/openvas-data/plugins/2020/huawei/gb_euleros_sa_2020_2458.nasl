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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.2458");
  script_version("2021-08-05T11:00:54+0000");
  script_cve_id("CVE-2020-14155");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-08-06 10:23:56 +0000 (Fri, 06 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-04 21:43:00 +0000 (Thu, 04 Mar 2021)");
  script_tag(name:"creation_date", value:"2020-11-05 08:49:34 +0000 (Thu, 05 Nov 2020)");
  script_name("Huawei EulerOS: Security Advisory for pcre (EulerOS-SA-2020-2458)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.6\.6");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-2458");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2458");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'pcre' package(s) announced via the EulerOS-SA-2020-2458 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libpcre in PCRE before 8.44 allows an integer overflow via a large number after a (?C substring.(CVE-2020-14155)");

  script_tag(name:"affected", value:"'pcre' package(s) on Huawei EulerOS Virtualization 3.0.6.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"pcre", rpm:"pcre~8.32~17.h11.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre-devel", rpm:"pcre-devel~8.32~17.h11.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
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
