# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852602");
  script_version("2020-01-31T08:04:39+0000");
  script_cve_id("CVE-2019-0199", "CVE-2019-0221");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-01-31 08:04:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-07-01 02:00:38 +0000 (Mon, 01 Jul 2019)");
  script_name("openSUSE: Security Advisory for tomcat (openSUSE-SU-2019:1673-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2019:1673-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-06/msg00090.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat'
  package(s) announced via the openSUSE-SU-2019:1673-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tomcat to version 9.0.20 fixes the following issues:

  Security issues fixed:

  - CVE-2019-0199: Fixed a denial of service in the HTTP/2 implementation
  related to streams with excessive numbers of SETTINGS frames
  (bsc#1131055).

  - CVE-2019-0221: Fixed a cross site scripting vulnerability with the SSI
  printenv command (bsc#1136085).

  Non-security issues fixed:

  - Increase maximum number of threads and open files for tomcat
  (bsc#1111966).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1673=1");

  script_tag(name:"affected", value:"'tomcat' package(s) on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~9.0.20~lp150.2.19.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~9.0.20~lp150.2.19.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-docs-webapp", rpm:"tomcat-docs-webapp~9.0.20~lp150.2.19.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-el-3_0-api", rpm:"tomcat-el-3_0-api~9.0.20~lp150.2.19.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-embed", rpm:"tomcat-embed~9.0.20~lp150.2.19.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-javadoc", rpm:"tomcat-javadoc~9.0.20~lp150.2.19.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsp-2_3-api", rpm:"tomcat-jsp-2_3-api~9.0.20~lp150.2.19.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsvc", rpm:"tomcat-jsvc~9.0.20~lp150.2.19.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~9.0.20~lp150.2.19.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-servlet-4_0-api", rpm:"tomcat-servlet-4_0-api~9.0.20~lp150.2.19.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~9.0.20~lp150.2.19.1", rls:"openSUSELeap15.0"))) {
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
