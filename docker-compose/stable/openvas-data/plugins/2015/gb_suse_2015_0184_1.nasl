# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850633");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2015-02-03 05:45:11 +0100 (Tue, 03 Feb 2015)");
  script_cve_id("CVE-2015-0235");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("openSUSE: Security Advisory for glibc (openSUSE-SU-2015:0184-1)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for glibc fixes the following security issue:

  CVE-2015-0235: A vulnerability was found and fixed in the GNU C Library,
  specifically in the function gethostbyname(), that could lead to a local
  or remote buffer overflow. (bsc#913646)");

  script_tag(name:"affected", value:"glibc on openSUSE 12.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"openSUSE-SU", value:"2015:0184-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE12\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE12.3") {
  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.17~4.17.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-debuginfo", rpm:"glibc-debuginfo~2.17~4.17.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-debugsource", rpm:"glibc-debugsource~2.17~4.17.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.17~4.17.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-debuginfo", rpm:"glibc-devel-debuginfo~2.17~4.17.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-static", rpm:"glibc-devel-static~2.17~4.17.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-extra", rpm:"glibc-extra~2.17~4.17.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-extra-debuginfo", rpm:"glibc-extra-debuginfo~2.17~4.17.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale", rpm:"glibc-locale~2.17~4.17.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale-debuginfo", rpm:"glibc-locale-debuginfo~2.17~4.17.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.17~4.17.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.17~4.17.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils-debuginfo", rpm:"glibc-utils-debuginfo~2.17~4.17.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils-debugsource", rpm:"glibc-utils-debugsource~2.17~4.17.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.17~4.17.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd-debuginfo", rpm:"nscd-debuginfo~2.17~4.17.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils-32bit", rpm:"glibc-utils-32bit~2.17~4.17.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils-debuginfo-32bit", rpm:"glibc-utils-debuginfo-32bit~2.17~4.17.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-html", rpm:"glibc-html~2.17~4.17.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.17~4.17.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-info", rpm:"glibc-info~2.17~4.17.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-obsolete", rpm:"glibc-obsolete~2.17~4.17.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-obsolete-debuginfo", rpm:"glibc-obsolete-debuginfo~2.17~4.17.1", rls:"openSUSE12.3"))) {
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
