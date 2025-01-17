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
  script_oid("1.3.6.1.4.1.25623.1.0.851549");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2017-05-09 06:50:33 +0200 (Tue, 09 May 2017)");
  script_cve_id("CVE-2016-5483", "CVE-2017-3302", "CVE-2017-3305", "CVE-2017-3308",
                "CVE-2017-3309", "CVE-2017-3329", "CVE-2017-3450", "CVE-2017-3452",
                "CVE-2017-3453", "CVE-2017-3456", "CVE-2017-3461", "CVE-2017-3462",
                "CVE-2017-3463", "CVE-2017-3464", "CVE-2017-3599", "CVE-2017-3600");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for mysql-community-server (openSUSE-SU-2017:1209-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-community-server'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mysql-community-server to version 5.6.36 fixes the
  following issues:

  These security issues were fixed:


  - CVE-2016-5483: Mysqldump failed to properly quote certain identifiers in
  SQL statements written to the dump output, allowing for execution of
  arbitrary commands (bsc#1029014)

  - CVE-2017-3305: MySQL client sent authentication request unencrypted even
  if SSL was required (aka Ridddle) (bsc#1029396).

  - CVE-2017-3308: Unspecified vulnerability in Server: DML (boo#1034850)

  - CVE-2017-3309: Unspecified vulnerability in Server: Optimizer
  (boo#1034850)

  - CVE-2017-3329: Unspecified vulnerability in Server: Thread (boo#1034850)

  - CVE-2017-3453: Unspecified vulnerability in Server: Optimizer
  (boo#1034850)

  - CVE-2017-3456: Unspecified vulnerability in Server: DML (boo#1034850)

  - CVE-2017-3461: Unspecified vulnerability in Server: Security
  (boo#1034850)

  - CVE-2017-3462: Unspecified vulnerability in Server: Security
  (boo#1034850)

  - CVE-2017-3463: Unspecified vulnerability in Server: Security
  (boo#1034850)

  - CVE-2017-3464: Unspecified vulnerability in Server: DDL (boo#1034850)

  - CVE-2017-3302: Crash in libmysqlclient.so (bsc#1022428).

  - CVE-2017-3450: Unspecified vulnerability Server: Memcached

  - CVE-2017-3452: Unspecified vulnerability Server: Optimizer

  - CVE-2017-3599: Unspecified vulnerability Server: Pluggable Auth

  - CVE-2017-3600: Unspecified vulnerability in Client: mysqldump
  (boo#1034850)

  - '--ssl-mode=REQUIRED' can be specified to require a secure connection
  (it fails if a secure connection cannot be obtained)


  These non-security issues were fixed:

  - Set the default umask to 077 in mysql-systemd-helper (boo#1020976)

  - Change permissions of the configuration dir/files to 755/644. Please
  note that storing the password in the /etc/my.cnf file is not safe. Use
  for example an option file that is accessible only by yourself
  (boo#889126)");

  script_tag(name:"affected", value:"mysql-community-server on openSUSE Leap 42.2, openSUSE Leap 42.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2017:1209-1");
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
  if(!isnull(res = isrpmvuln(pkg:"libmysql56client18", rpm:"libmysql56client18~5.6.36~24.3.3", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client18-debuginfo", rpm:"libmysql56client18-debuginfo~5.6.36~24.3.3", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client_r18", rpm:"libmysql56client_r18~5.6.36~24.3.3", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server", rpm:"mysql-community-server~5.6.36~24.3.3", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-bench", rpm:"mysql-community-server-bench~5.6.36~24.3.3", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-bench-debuginfo", rpm:"mysql-community-server-bench-debuginfo~5.6.36~24.3.3", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-client", rpm:"mysql-community-server-client~5.6.36~24.3.3", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-client-debuginfo", rpm:"mysql-community-server-client-debuginfo~5.6.36~24.3.3", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-debuginfo", rpm:"mysql-community-server-debuginfo~5.6.36~24.3.3", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-debugsource", rpm:"mysql-community-server-debugsource~5.6.36~24.3.3", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-errormessages", rpm:"mysql-community-server-errormessages~5.6.36~24.3.3", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-test", rpm:"mysql-community-server-test~5.6.36~24.3.3", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-test-debuginfo", rpm:"mysql-community-server-test-debuginfo~5.6.36~24.3.3", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-tools", rpm:"mysql-community-server-tools~5.6.36~24.3.3", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-tools-debuginfo", rpm:"mysql-community-server-tools-debuginfo~5.6.36~24.3.3", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client18-32bit", rpm:"libmysql56client18-32bit~5.6.36~24.3.3", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client18-debuginfo-32bit", rpm:"libmysql56client18-debuginfo-32bit~5.6.36~24.3.3", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client_r18-32bit", rpm:"libmysql56client_r18-32bit~5.6.36~24.3.3", rls:"openSUSELeap42.2"))) {
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
  if(!isnull(res = isrpmvuln(pkg:"libmysql56client18", rpm:"libmysql56client18~5.6.36~25.3", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client18-debuginfo", rpm:"libmysql56client18-debuginfo~5.6.36~25.3", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client_r18", rpm:"libmysql56client_r18~5.6.36~25.3", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server", rpm:"mysql-community-server~5.6.36~25.3", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-bench", rpm:"mysql-community-server-bench~5.6.36~25.3", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-bench-debuginfo", rpm:"mysql-community-server-bench-debuginfo~5.6.36~25.3", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-client", rpm:"mysql-community-server-client~5.6.36~25.3", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-client-debuginfo", rpm:"mysql-community-server-client-debuginfo~5.6.36~25.3", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-debuginfo", rpm:"mysql-community-server-debuginfo~5.6.36~25.3", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-debugsource", rpm:"mysql-community-server-debugsource~5.6.36~25.3", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-errormessages", rpm:"mysql-community-server-errormessages~5.6.36~25.3", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-test", rpm:"mysql-community-server-test~5.6.36~25.3", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-test-debuginfo", rpm:"mysql-community-server-test-debuginfo~5.6.36~25.3", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-tools", rpm:"mysql-community-server-tools~5.6.36~25.3", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-tools-debuginfo", rpm:"mysql-community-server-tools-debuginfo~5.6.36~25.3", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client18-32bit", rpm:"libmysql56client18-32bit~5.6.36~25.3", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client18-debuginfo-32bit", rpm:"libmysql56client18-debuginfo-32bit~5.6.36~25.3", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client_r18-32bit", rpm:"libmysql56client_r18-32bit~5.6.36~25.3", rls:"openSUSELeap42.1"))) {
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
