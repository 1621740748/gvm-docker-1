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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0984.1");
  script_cve_id("CVE-2009-5026", "CVE-2012-0075", "CVE-2012-0087", "CVE-2012-0101", "CVE-2012-0102", "CVE-2012-0114", "CVE-2012-0484", "CVE-2012-0490", "CVE-2012-2122");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:27 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-17 20:26:00 +0000 (Tue, 17 Dec 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0984-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2|SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0984-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120984-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MySQL' package(s) announced via the SUSE-SU-2012:0984-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MySQL has been upgraded to version 5.0.96 to fix several vulnerabilities.

Security Issue reference:

 * CVE-2012-2122
>
 * CVE-2012-0075
>
 * CVE-2012-0114
>
 * CVE-2012-0490
>
 * CVE-2012-0484
>
 * CVE-2012-0102
>
 * CVE-2012-0101
>
 * CVE-2012-0087
>
 * CVE-2009-5026
>");

  script_tag(name:"affected", value:"'MySQL' package(s) on SUSE Linux Enterprise Software Development Kit 11 SP2, SUSE Linux Enterprise Software Development Kit 11 SP1, SUSE Linux Enterprise Server 11 SP2, SUSE Linux Enterprise Server 11 SP1, SUSE Linux Enterprise Desktop 11 SP2, SUSE Linux Enterprise Desktop 11 SP1.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient15", rpm:"libmysqlclient15~5.0.96~0.4.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient_r15", rpm:"libmysqlclient_r15~5.0.96~0.4.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.0.96~0.4.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-Max", rpm:"mysql-Max~5.0.96~0.4.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-client", rpm:"mysql-client~5.0.96~0.4.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-tools", rpm:"mysql-tools~5.0.96~0.4.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient15-32bit", rpm:"libmysqlclient15-32bit~5.0.96~0.4.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient15-x86", rpm:"libmysqlclient15-x86~5.0.96~0.4.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient15", rpm:"libmysqlclient15~5.0.96~0.4.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient_r15", rpm:"libmysqlclient_r15~5.0.96~0.4.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.0.96~0.4.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-Max", rpm:"mysql-Max~5.0.96~0.4.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-client", rpm:"mysql-client~5.0.96~0.4.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-tools", rpm:"mysql-tools~5.0.96~0.4.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient15-32bit", rpm:"libmysqlclient15-32bit~5.0.96~0.4.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient15-x86", rpm:"libmysqlclient15-x86~5.0.96~0.4.1", rls:"SLES11.0SP1"))) {
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
