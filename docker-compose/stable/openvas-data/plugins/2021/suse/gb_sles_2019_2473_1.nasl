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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2473.1");
  script_cve_id("CVE-2019-9511", "CVE-2019-9513");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:16 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-30 02:36:00 +0000 (Sat, 30 Jan 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2473-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2473-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192473-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nghttp2' package(s) announced via the SUSE-SU-2019:2473-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nghttp2 fixes the following issues:

Security issues fixed:
CVE-2019-9513: Fixed HTTP/2 implementation that is vulnerable to
 resource loops, potentially leading to a denial of service (bsc#1146184).

CVE-2019-9511: Fixed HTTP/2 implementations that are vulnerable to
 window size manipulation and stream prioritization manipulation,
 potentially leading to a denial of service (bsc#11461).

Bug fixes and enhancements:
Fixed mistake in spec file (bsc#1125689)

Fixed build issue with boost 1.70.0 (bsc#1134616)

Feature: Add W&S module (FATE#326776, bsc#1112438)");

  script_tag(name:"affected", value:"'nghttp2' package(s) on SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Basesystem 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14", rpm:"libnghttp2-14~1.39.2~3.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14-debuginfo", rpm:"libnghttp2-14-debuginfo~1.39.2~3.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-devel", rpm:"libnghttp2-devel~1.39.2~3.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_asio-devel", rpm:"libnghttp2_asio-devel~1.39.2~3.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_asio1", rpm:"libnghttp2_asio1~1.39.2~3.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_asio1-debuginfo", rpm:"libnghttp2_asio1-debuginfo~1.39.2~3.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nghttp2-debuginfo", rpm:"nghttp2-debuginfo~1.39.2~3.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nghttp2-debugsource", rpm:"nghttp2-debugsource~1.39.2~3.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14-32bit", rpm:"libnghttp2-14-32bit~1.39.2~3.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14-32bit-debuginfo", rpm:"libnghttp2-14-32bit-debuginfo~1.39.2~3.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14", rpm:"libnghttp2-14~1.39.2~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14-debuginfo", rpm:"libnghttp2-14-debuginfo~1.39.2~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-devel", rpm:"libnghttp2-devel~1.39.2~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_asio-devel", rpm:"libnghttp2_asio-devel~1.39.2~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_asio1", rpm:"libnghttp2_asio1~1.39.2~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_asio1-debuginfo", rpm:"libnghttp2_asio1-debuginfo~1.39.2~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nghttp2-debuginfo", rpm:"nghttp2-debuginfo~1.39.2~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nghttp2-debugsource", rpm:"nghttp2-debugsource~1.39.2~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14-32bit", rpm:"libnghttp2-14-32bit~1.39.2~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-14-32bit-debuginfo", rpm:"libnghttp2-14-32bit-debuginfo~1.39.2~3.3.1", rls:"SLES15.0"))) {
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
