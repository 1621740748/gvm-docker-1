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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2742.1");
  script_cve_id("CVE-2020-17507");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:53 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-30 18:15:00 +0000 (Wed, 30 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2742-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2742-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202742-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libqt5-qtbase' package(s) announced via the SUSE-SU-2020:2742-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libqt5-qtbase fixes the following issues:

CVE-2020-17507: Fixed a buffer overflow in XBM parser (bsc#1176315)

Fixed various issues discovered by fuzzing:

Made handling of XDG_RUNTIME_DIR more secure (bsc#1172515):");

  script_tag(name:"affected", value:"'libqt5-qtbase' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"libQt5OpenGLExtensions-devel-static", rpm:"libQt5OpenGLExtensions-devel-static~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5-mysql", rpm:"libQt5Sql5-mysql~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5-mysql-debuginfo", rpm:"libQt5Sql5-mysql-debuginfo~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5-postgresql", rpm:"libQt5Sql5-postgresql~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5-postgresql-debuginfo", rpm:"libQt5Sql5-postgresql-debuginfo~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5-unixODBC", rpm:"libQt5Sql5-unixODBC~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5-unixODBC-debuginfo", rpm:"libQt5Sql5-unixODBC-debuginfo~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtbase-debugsource", rpm:"libqt5-qtbase-debugsource~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtbase-platformtheme-gtk3", rpm:"libqt5-qtbase-platformtheme-gtk3~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtbase-platformtheme-gtk3-debuginfo", rpm:"libqt5-qtbase-platformtheme-gtk3-debuginfo~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Concurrent-devel", rpm:"libQt5Concurrent-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Concurrent5", rpm:"libQt5Concurrent5~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Concurrent5-debuginfo", rpm:"libQt5Concurrent5-debuginfo~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Core-devel", rpm:"libQt5Core-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Core5", rpm:"libQt5Core5~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Core5-debuginfo", rpm:"libQt5Core5-debuginfo~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5DBus-devel", rpm:"libQt5DBus-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5DBus-devel-debuginfo", rpm:"libQt5DBus-devel-debuginfo~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5DBus5", rpm:"libQt5DBus5~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5DBus5-debuginfo", rpm:"libQt5DBus5-debuginfo~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Gui-devel", rpm:"libQt5Gui-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Gui5", rpm:"libQt5Gui5~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Gui5-debuginfo", rpm:"libQt5Gui5-debuginfo~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5KmsSupport-devel-static", rpm:"libQt5KmsSupport-devel-static~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Network-devel", rpm:"libQt5Network-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Network5", rpm:"libQt5Network5~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Network5-debuginfo", rpm:"libQt5Network5-debuginfo~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5OpenGL-devel", rpm:"libQt5OpenGL-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5OpenGL5", rpm:"libQt5OpenGL5~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5OpenGL5-debuginfo", rpm:"libQt5OpenGL5-debuginfo~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PlatformHeaders-devel", rpm:"libQt5PlatformHeaders-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PlatformSupport-devel-static", rpm:"libQt5PlatformSupport-devel-static~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PrintSupport-devel", rpm:"libQt5PrintSupport-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PrintSupport5", rpm:"libQt5PrintSupport5~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PrintSupport5-debuginfo", rpm:"libQt5PrintSupport5-debuginfo~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql-devel", rpm:"libQt5Sql-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5", rpm:"libQt5Sql5~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5-debuginfo", rpm:"libQt5Sql5-debuginfo~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5-sqlite", rpm:"libQt5Sql5-sqlite~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5-sqlite-debuginfo", rpm:"libQt5Sql5-sqlite-debuginfo~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Test-devel", rpm:"libQt5Test-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Test5", rpm:"libQt5Test5~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Test5-debuginfo", rpm:"libQt5Test5-debuginfo~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Widgets-devel", rpm:"libQt5Widgets-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Widgets5", rpm:"libQt5Widgets5~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Widgets5-debuginfo", rpm:"libQt5Widgets5-debuginfo~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Xml-devel", rpm:"libQt5Xml-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Xml5", rpm:"libQt5Xml5~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Xml5-debuginfo", rpm:"libQt5Xml5-debuginfo~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtbase-common-devel", rpm:"libqt5-qtbase-common-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtbase-common-devel-debuginfo", rpm:"libqt5-qtbase-common-devel-debuginfo~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtbase-devel", rpm:"libqt5-qtbase-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Core-private-headers-devel", rpm:"libQt5Core-private-headers-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5DBus-private-headers-devel", rpm:"libQt5DBus-private-headers-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Gui-private-headers-devel", rpm:"libQt5Gui-private-headers-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5KmsSupport-private-headers-devel", rpm:"libQt5KmsSupport-private-headers-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Network-private-headers-devel", rpm:"libQt5Network-private-headers-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5OpenGL-private-headers-devel", rpm:"libQt5OpenGL-private-headers-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PlatformSupport-private-headers-devel", rpm:"libQt5PlatformSupport-private-headers-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PrintSupport-private-headers-devel", rpm:"libQt5PrintSupport-private-headers-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql-private-headers-devel", rpm:"libQt5Sql-private-headers-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Test-private-headers-devel", rpm:"libQt5Test-private-headers-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Widgets-private-headers-devel", rpm:"libQt5Widgets-private-headers-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtbase-private-headers-devel", rpm:"libqt5-qtbase-private-headers-devel~5.12.7~4.6.1", rls:"SLES15.0SP2"))) {
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
