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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.2170");
  script_version("2021-07-13T10:05:59+0000");
  script_cve_id("CVE-2014-10401", "CVE-2019-20919");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-07-13 10:05:59 +0000 (Tue, 13 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-10-12 10:21:51 +0000 (Mon, 12 Oct 2020)");
  script_name("Huawei EulerOS: Security Advisory for perl-DBI (EulerOS-SA-2020-2170)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP9");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-2170");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2170");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'perl-DBI' package(s) announced via the EulerOS-SA-2020-2170 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in the DBI module before 1.643 for Perl. The hv_fetch() documentation requires checking for NULL and the code does that. But, shortly thereafter, it calls SvOK(profile), causing a NULL pointer dereference.(CVE-2019-20919)

An issue was discovered in the DBI module before 1.632 for Perl. DBD::File drivers can open files from folders other than those specifically passed via the f_dir attribute.(CVE-2014-10401)");

  script_tag(name:"affected", value:"'perl-DBI' package(s) on Huawei EulerOS V2.0SP9.");

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

  if(!isnull(res = isrpmvuln(pkg:"perl-DBI", rpm:"perl-DBI~1.642~2.h2.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
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
