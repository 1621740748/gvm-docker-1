# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851357");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2016-06-28 05:26:40 +0200 (Tue, 28 Jun 2016)");
  script_cve_id("CVE-2016-0505", "CVE-2016-0546", "CVE-2016-0596", "CVE-2016-0597",
                "CVE-2016-0598", "CVE-2016-0600", "CVE-2016-0606", "CVE-2016-0608",
                "CVE-2016-0609", "CVE-2016-0616", "CVE-2016-0640", "CVE-2016-0641",
                "CVE-2016-0642", "CVE-2016-0643", "CVE-2016-0644", "CVE-2016-0646",
                "CVE-2016-0647", "CVE-2016-0648", "CVE-2016-0649", "CVE-2016-0650",
                "CVE-2016-0651", "CVE-2016-0655", "CVE-2016-0666", "CVE-2016-0668",
                "CVE-2016-2047");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for mariadb (openSUSE-SU-2016:1686-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"mariadb was updated to version 10.0.25 to fix 25 security issues.

  These security issues were fixed:

  - CVE-2016-0505: Unspecified vulnerability allowed remote authenticated
  users to affect availability via unknown vectors related to Options
  (bsc#980904).

  - CVE-2016-0546: Unspecified vulnerability allowed local users to affect
  confidentiality, integrity, and availability via unknown vectors related
  to Client (bsc#980904).

  - CVE-2016-0596: Unspecified vulnerability allowed remote authenticated
  users to affect availability via vectors related to DML (bsc#980904).

  - CVE-2016-0597: Unspecified vulnerability allowed remote authenticated
  users to affect availability via unknown vectors related to Optimizer
  (bsc#980904).

  - CVE-2016-0598: Unspecified vulnerability allowed remote authenticated
  users to affect availability via vectors related to DML (bsc#980904).

  - CVE-2016-0600: Unspecified vulnerability allowed remote authenticated
  users to affect availability via unknown vectors related to InnoDB
  (bsc#980904).

  - CVE-2016-0606: Unspecified vulnerability allowed remote authenticated
  users to affect integrity via unknown vectors related to encryption
  (bsc#980904).

  - CVE-2016-0608: Unspecified vulnerability allowed remote authenticated
  users to affect availability via vectors related to UDF (bsc#980904).

  - CVE-2016-0609: Unspecified vulnerability allowed remote authenticated
  users to affect availability via unknown vectors related to privileges
  (bsc#980904).

  - CVE-2016-0616: Unspecified vulnerability allowed remote authenticated
  users to affect availability via unknown vectors related to Optimizer
  (bsc#980904).

  - CVE-2016-0640: Unspecified vulnerability allowed local users to affect
  integrity and availability via vectors related to DML (bsc#980904).

  - CVE-2016-0641: Unspecified vulnerability allowed local users to affect
  confidentiality and availability via vectors related to MyISAM
  (bsc#980904).

  - CVE-2016-0642: Unspecified vulnerability allowed local users to affect
  integrity and availability via vectors related to Federated (bsc#980904).

  - CVE-2016-0643: Unspecified vulnerability allowed local users to affect
  confidentiality via vectors related to DML (bsc#980904).

  - CVE-2016-0644: Unspecified vulnerability allowed local users to affect
  availability via vectors related to DDL (bsc#980904).

  - CVE-2016-0646: Unspecified vulnerability allowed local users to affect
  availability via vectors related to DML (bsc#980904).

  - CVE-2016-0647: Unspecified vulnerability allowed local users to affect
  availability via vecto ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"mariadb on openSUSE Leap 42.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:1686-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.1") {
  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient-devel", rpm:"libmysqlclient-devel~10.0.25~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18", rpm:"libmysqlclient18~10.0.25~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-debuginfo", rpm:"libmysqlclient18-debuginfo~10.0.25~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient_r18", rpm:"libmysqlclient_r18~10.0.25~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqld-devel", rpm:"libmysqld-devel~10.0.25~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqld18", rpm:"libmysqld18~10.0.25~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqld18-debuginfo", rpm:"libmysqld18-debuginfo~10.0.25~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.0.25~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-bench", rpm:"mariadb-bench~10.0.25~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-bench-debuginfo", rpm:"mariadb-bench-debuginfo~10.0.25~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.0.25~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client-debuginfo", rpm:"mariadb-client-debuginfo~10.0.25~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-debuginfo", rpm:"mariadb-debuginfo~10.0.25~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-debugsource", rpm:"mariadb-debugsource~10.0.25~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.0.25~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-test", rpm:"mariadb-test~10.0.25~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-test-debuginfo", rpm:"mariadb-test-debuginfo~10.0.25~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.0.25~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools-debuginfo", rpm:"mariadb-tools-debuginfo~10.0.25~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-32bit", rpm:"libmysqlclient18-32bit~10.0.25~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-debuginfo-32bit", rpm:"libmysqlclient18-debuginfo-32bit~10.0.25~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient_r18-32bit", rpm:"libmysqlclient_r18-32bit~10.0.25~6.1", rls:"openSUSELeap42.1"))) {
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
