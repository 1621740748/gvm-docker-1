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
  script_oid("1.3.6.1.4.1.25623.1.0.851537");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2017-04-20 06:34:07 +0200 (Thu, 20 Apr 2017)");
  script_cve_id("CVE-2016-2775", "CVE-2016-6170", "CVE-2017-3136", "CVE-2017-3137", "CVE-2017-3138");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for bind (openSUSE-SU-2017:1063-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bind fixes the following issues:

  CVE-2017-3137 (bsc#1033467): Mistaken assumptions about the ordering of
  records in the answer section of a response containing CNAME or DNAME
  resource records could have been exploited to cause a denial of service of
  a bind server performing recursion.

  CVE-2017-3136 (bsc#1033466): An attacker could have constructed a query
  that would cause a denial
  of service of servers configured to use DNS64.

  CVE-2017-3138 (bsc#1033468): An attacker with access to the BIND control
  channel could have caused the server to stop by triggering an assertion
  failure.

  CVE-2016-6170 (bsc#987866): Primary DNS servers could have caused a denial
  of service of secondary DNS servers via a large AXFR response. IXFR
  servers could have caused a denial of service of IXFR clients via a large
  IXFR response. Remote authenticated users could have caused a denial of
  service of primary DNS servers via a large UPDATE message.

  CVE-2016-2775 (bsc#989528): When lwresd or the named lwres option were
  enabled, bind allowed remote attackers to cause a denial of service
  (daemon crash) via a long request that uses the lightweight resolver
  protocol.

  One additional non-security bug was fixed:

  The default umask was changed to 077. (bsc#1020983)


  This update was imported from the SUSE:SLE-12-SP1:Update update project.");

  script_tag(name:"affected", value:"bind on openSUSE Leap 42.2, openSUSE Leap 42.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2017:1063-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.2|openSUSELeap42\.1)");
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
  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.9.9P1~48.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.9.9P1~48.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.9.9P1~48.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.9.9P1~48.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.9.9P1~48.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.9.9P1~48.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs-debuginfo", rpm:"bind-libs-debuginfo~9.9.9P1~48.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-lwresd", rpm:"bind-lwresd~9.9.9P1~48.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-lwresd-debuginfo", rpm:"bind-lwresd-debuginfo~9.9.9P1~48.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.9.9P1~48.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils-debuginfo", rpm:"bind-utils-debuginfo~9.9.9P1~48.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs-32bit", rpm:"bind-libs-32bit~9.9.9P1~48.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs-debuginfo-32bit", rpm:"bind-libs-debuginfo-32bit~9.9.9P1~48.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.9.9P1~48.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap42.1") {
  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.9.9P1~51.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.9.9P1~51.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.9.9P1~51.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.9.9P1~51.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.9.9P1~51.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.9.9P1~51.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs-debuginfo", rpm:"bind-libs-debuginfo~9.9.9P1~51.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-lwresd", rpm:"bind-lwresd~9.9.9P1~51.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-lwresd-debuginfo", rpm:"bind-lwresd-debuginfo~9.9.9P1~51.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.9.9P1~51.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils-debuginfo", rpm:"bind-utils-debuginfo~9.9.9P1~51.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.9.9P1~51.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs-32bit", rpm:"bind-libs-32bit~9.9.9P1~51.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs-debuginfo-32bit", rpm:"ind-libs-debuginfo-32bit~9.9.9P1~51.1", rls:"openSUSELeap42.1"))) {
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
