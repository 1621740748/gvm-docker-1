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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2346.1");
  script_cve_id("CVE-2018-10196");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:56 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-13 11:15:00 +0000 (Thu, 13 May 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2346-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2346-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202346-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'graphviz' package(s) announced via the SUSE-SU-2020:2346-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for graphviz fixes the following issues:

CVE-2018-10196: Fixed a null dereference in rebuild_vlis (bsc#1093447).");

  script_tag(name:"affected", value:"'graphviz' package(s) on SUSE Linux Enterprise Module for Server Applications 15-SP1, SUSE Linux Enterprise Module for Development Tools 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise High Availability 15-SP1, SUSE Linux Enterprise High Availability 15.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"graphviz-addons-debuginfo", rpm:"graphviz-addons-debuginfo~2.40.1~6.6.8", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-addons-debugsource", rpm:"graphviz-addons-debugsource~2.40.1~6.6.8", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-tcl", rpm:"graphviz-tcl~2.40.1~6.6.8", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-tcl-debuginfo", rpm:"graphviz-tcl-debuginfo~2.40.1~6.6.8", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-perl", rpm:"graphviz-perl~2.40.1~6.6.8", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-perl-debuginfo", rpm:"graphviz-perl-debuginfo~2.40.1~6.6.8", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz", rpm:"graphviz~2.40.1~6.6.4", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-debuginfo", rpm:"graphviz-debuginfo~2.40.1~6.6.4", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-debugsource", rpm:"graphviz-debugsource~2.40.1~6.6.4", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-devel", rpm:"graphviz-devel~2.40.1~6.6.4", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-plugins-core", rpm:"graphviz-plugins-core~2.40.1~6.6.4", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-plugins-core-debuginfo", rpm:"graphviz-plugins-core-debuginfo~2.40.1~6.6.4", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphviz6", rpm:"libgraphviz6~2.40.1~6.6.4", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphviz6-debuginfo", rpm:"libgraphviz6-debuginfo~2.40.1~6.6.4", rls:"SLES15.0SP1"))) {
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
