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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1202");
  script_version("2021-08-04T11:01:00+0000");
  script_cve_id("CVE-2018-16539", "CVE-2018-16541");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-08-04 11:01:00 +0000 (Wed, 04 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-07 15:57:00 +0000 (Thu, 07 Mar 2019)");
  script_tag(name:"creation_date", value:"2020-01-23 11:34:25 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for ghostscript (EulerOS-SA-2019-1202)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-2\.5\.4");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1202");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1202");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'ghostscript' package(s) announced via the EulerOS-SA-2019-1202 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the ghostscript did not properly restrict access to files open prior to enabling the -dSAFER mode. An attacker could possibly exploit this to bypass the -dSAFER protection and disclose the content of affected files via a specially crafted PostScript document.CVE-2018-16539

It was discovered that the ghostscript device cleanup did not properly handle devices replaced with a null device. An attacker could possibly exploit this to bypass the -dSAFER protection and crash ghostscript or, possibly, execute arbitrary code in the ghostscript context via a specially crafted PostScript document.CVE-2018-16541");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Huawei EulerOS Virtualization 2.5.4.");

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

if(release == "EULEROSVIRT-2.5.4") {

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.07~29.2.h4", rls:"EULEROSVIRT-2.5.4"))) {
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
