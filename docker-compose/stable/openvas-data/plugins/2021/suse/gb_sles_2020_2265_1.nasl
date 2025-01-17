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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2265.1");
  script_cve_id("CVE-2020-14349", "CVE-2020-14350");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:56 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-18 12:15:00 +0000 (Fri, 18 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2265-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2265-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202265-1/");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/12/release-12-4.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql12' package(s) announced via the SUSE-SU-2020:2265-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql12 fixes the following issues:

update to 12.4:
 * CVE-2020-14349, bsc#1175193: Set a secure search_path in logical
 replication walsenders and apply workers
 * CVE-2020-14350, bsc#1175194: Make contrib modules' installation
 scripts more secure.
 * [link moved to references]");

  script_tag(name:"affected", value:"'postgresql12' package(s) on SUSE Linux Enterprise Module for Server Applications 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libecpg6", rpm:"libecpg6~12.4~8.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-debuginfo", rpm:"libecpg6-debuginfo~12.4~8.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-contrib", rpm:"postgresql12-contrib~12.4~8.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-contrib-debuginfo", rpm:"postgresql12-contrib-debuginfo~12.4~8.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-debuginfo", rpm:"postgresql12-debuginfo~12.4~8.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-debugsource", rpm:"postgresql12-debugsource~12.4~8.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-devel", rpm:"postgresql12-devel~12.4~8.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-devel-debuginfo", rpm:"postgresql12-devel-debuginfo~12.4~8.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-plperl", rpm:"postgresql12-plperl~12.4~8.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-plperl-debuginfo", rpm:"postgresql12-plperl-debuginfo~12.4~8.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-plpython", rpm:"postgresql12-plpython~12.4~8.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-plpython-debuginfo", rpm:"postgresql12-plpython-debuginfo~12.4~8.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-pltcl", rpm:"postgresql12-pltcl~12.4~8.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-pltcl-debuginfo", rpm:"postgresql12-pltcl-debuginfo~12.4~8.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-server", rpm:"postgresql12-server~12.4~8.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-server-debuginfo", rpm:"postgresql12-server-debuginfo~12.4~8.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-server-devel", rpm:"postgresql12-server-devel~12.4~8.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-server-devel-debuginfo", rpm:"postgresql12-server-devel-debuginfo~12.4~8.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-docs", rpm:"postgresql12-docs~12.4~8.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~12.4~8.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-debuginfo", rpm:"libpq5-debuginfo~12.4~8.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12", rpm:"postgresql12~12.4~8.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-32bit", rpm:"libpq5-32bit~12.4~8.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-32bit-debuginfo", rpm:"libpq5-32bit-debuginfo~12.4~8.6.1", rls:"SLES15.0SP2"))) {
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
