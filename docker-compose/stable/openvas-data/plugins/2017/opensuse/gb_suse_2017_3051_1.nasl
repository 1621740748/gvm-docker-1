# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851649");
  script_version("2020-06-03T08:38:58+0000");
  script_tag(name:"last_modification", value:"2020-06-03 08:38:58 +0000 (Wed, 03 Jun 2020)");
  script_tag(name:"creation_date", value:"2017-11-23 07:28:19 +0100 (Thu, 23 Nov 2017)");
  script_cve_id("CVE-2017-16641", "CVE-2017-16660", "CVE-2017-16661", "CVE-2017-16785");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for cacti (openSUSE-SU-2017:3051-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cacti'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cacti, cacti-spine to version 1.1.28 fixes the following
  issues:

  - CVE-2017-16641: Potential code execution vulnerability in RRDtool
  functions (boo#1067166)

  - CVE-2017-16660: Remote execution vulnerability in logging function
  (boo#1067164)

  - CVE-2017-16661: Arbitrary file read vulnerability in view log file
  (boo#1067163)

  - CVE-2017-16785: Reflection XSS vulnerability (boo#1068028)

  This update to version 1.1.28 also contains a number of upstream bug fixes
  and improvements.");

  script_tag(name:"affected", value:"cacti, on openSUSE Leap 42.3, openSUSE Leap 42.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2017:3051-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.2|openSUSELeap42\.3)");
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
  if(!isnull(res = isrpmvuln(pkg:"cacti-spine", rpm:"cacti-spine~1.1.28~7.13.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine-debuginfo", rpm:"cacti-spine-debuginfo~1.1.28~7.13.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine-debugsource", rpm:"cacti-spine-debugsource~1.1.28~7.13.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti", rpm:"cacti~1.1.28~16.13.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti-doc", rpm:"cacti-doc~1.1.28~16.13.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"cacti-spine", rpm:"cacti-spine~1.1.28~20.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine-debuginfo", rpm:"cacti-spine-debuginfo~1.1.28~20.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine-debugsource", rpm:"cacti-spine-debugsource~1.1.28~20.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti", rpm:"cacti~1.1.28~29.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti-doc", rpm:"cacti-doc~1.1.28~29.1", rls:"openSUSELeap42.3"))) {
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
