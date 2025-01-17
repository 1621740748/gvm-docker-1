# Copyright (C) 2012 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850178");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2012-08-02 20:16:33 +0530 (Thu, 02 Aug 2012)");
  script_cve_id("CVE-2011-3922");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"openSUSE-SU", value:"2012:0091-1");
  script_name("openSUSE: Security Advisory for libqt4 (openSUSE-SU-2012:0091-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libqt4'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.4|openSUSE11\.3)");

  script_tag(name:"affected", value:"libqt4 on openSUSE 11.4, openSUSE 11.3");

  script_tag(name:"insight", value:"A stack-based buffer overflow in the glyph handling of
  libqt4's harfbuzz has been fixed. CVE-2011-3922 has been
  assigned to this issue.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE11.4") {
  if(!isnull(res = isrpmvuln(pkg:"libQtWebKit-devel", rpm:"libQtWebKit-devel~4.7.1~8.17.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQtWebKit4", rpm:"libQtWebKit4~4.7.1~8.17.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4", rpm:"libqt4~4.7.1~8.17.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-devel", rpm:"libqt4-devel~4.7.1~8.17.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-qt3support", rpm:"libqt4-qt3support~4.7.1~8.17.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql", rpm:"libqt4-sql~4.7.1~8.17.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-sqlite", rpm:"libqt4-sql-sqlite~4.7.1~8.17.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-x11", rpm:"libqt4-x11~4.7.1~8.17.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQtWebKit4-32bit", rpm:"libQtWebKit4-32bit~4.7.1~8.17.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-32bit", rpm:"libqt4-32bit~4.7.1~8.17.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-qt3support-32bit", rpm:"libqt4-qt3support-32bit~4.7.1~8.17.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-32bit", rpm:"libqt4-sql-32bit~4.7.1~8.17.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-sqlite-32bit", rpm:"libqt4-sql-sqlite-32bit~4.7.1~8.17.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-x11-32bit", rpm:"libqt4-x11-32bit~4.7.1~8.17.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSE11.3") {
  if(!isnull(res = isrpmvuln(pkg:"libQtWebKit-devel", rpm:"libQtWebKit-devel~4.6.3~2.7.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQtWebKit4", rpm:"libQtWebKit4~4.6.3~2.7.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4", rpm:"libqt4~4.6.3~2.7.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-devel", rpm:"libqt4-devel~4.6.3~2.7.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-qt3support", rpm:"libqt4-qt3support~4.6.3~2.7.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql", rpm:"libqt4-sql~4.6.3~2.7.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-sqlite", rpm:"libqt4-sql-sqlite~4.6.3~2.7.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-x11", rpm:"libqt4-x11~4.6.3~2.7.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQtWebKit4-32bit", rpm:"libQtWebKit4-32bit~4.6.3~2.7.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-32bit", rpm:"libqt4-32bit~4.6.3~2.7.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-qt3support-32bit", rpm:"libqt4-qt3support-32bit~4.6.3~2.7.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-32bit", rpm:"libqt4-sql-32bit~4.6.3~2.7.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-sqlite-32bit", rpm:"libqt4-sql-sqlite-32bit~4.6.3~2.7.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-x11-32bit", rpm:"libqt4-x11-32bit~4.6.3~2.7.1", rls:"openSUSE11.3"))) {
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
