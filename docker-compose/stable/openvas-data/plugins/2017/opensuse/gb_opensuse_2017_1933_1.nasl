# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851583");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2017-07-25 07:25:09 +0200 (Tue, 25 Jul 2017)");
  script_cve_id("CVE-2017-1000083");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for evince (openSUSE-SU-2017:1933-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'evince'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for evince fixes the following issues:

  - CVE-2017-1000083: Remote attackers could have used the comicbook mode of
  evince to inject shell code. (bsc#1046856, bgo#784630)

  This update was imported from the SUSE:SLE-12-SP2:Update update project.");

  script_tag(name:"affected", value:"evince on openSUSE Leap 42.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2017:1933-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.2") {
  if(!isnull(res = isrpmvuln(pkg:"evince", rpm:"evince~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-browser-plugin", rpm:"evince-browser-plugin~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-browser-plugin-debuginfo", rpm:"evince-browser-plugin-debuginfo~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-debuginfo", rpm:"evince-debuginfo~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-debugsource", rpm:"evince-debugsource~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-devel", rpm:"evince-devel~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-comicsdocument", rpm:"evince-plugin-comicsdocument~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-comicsdocument-debuginfo", rpm:"evince-plugin-comicsdocument-debuginfo~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-djvudocument", rpm:"evince-plugin-djvudocument~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-djvudocument-debuginfo", rpm:"evince-plugin-djvudocument-debuginfo~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-dvidocument", rpm:"evince-plugin-dvidocument~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-dvidocument-debuginfo", rpm:"evince-plugin-dvidocument-debuginfo~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-pdfdocument", rpm:"evince-plugin-pdfdocument~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-pdfdocument-debuginfo", rpm:"evince-plugin-pdfdocument-debuginfo~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-psdocument", rpm:"evince-plugin-psdocument~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-psdocument-debuginfo", rpm:"evince-plugin-psdocument-debuginfo~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-tiffdocument", rpm:"evince-plugin-tiffdocument~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-tiffdocument-debuginfo", rpm:"evince-plugin-tiffdocument-debuginfo~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-xpsdocument", rpm:"evince-plugin-xpsdocument~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-xpsdocument-debuginfo", rpm:"evince-plugin-xpsdocument-debuginfo~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libevdocument3-4", rpm:"libevdocument3-4~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libevdocument3-4-debuginfo", rpm:"libevdocument3-4-debuginfo~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libevview3-3", rpm:"libevview3-3~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libevview3-3-debuginfo", rpm:"libevview3-3-debuginfo~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nautilus-evince", rpm:"nautilus-evince~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nautilus-evince-debuginfo", rpm:"nautilus-evince-debuginfo~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-EvinceDocument-3_0", rpm:"typelib-1_0-EvinceDocument-3_0~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-EvinceView-3_0", rpm:"typelib-1_0-EvinceView-3_0~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-lang", rpm:"evince-lang~3.20.1~2.3.1", rls:"openSUSELeap42.2"))) {
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
