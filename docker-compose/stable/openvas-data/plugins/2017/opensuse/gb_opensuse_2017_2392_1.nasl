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
  script_oid("1.3.6.1.4.1.25623.1.0.851614");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2017-09-09 07:21:17 +0200 (Sat, 09 Sep 2017)");
  script_cve_id("CVE-2017-7546", "CVE-2017-7547", "CVE-2017-7548");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for postgresql94 (openSUSE-SU-2017:2392-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql94'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql94 fixes the following issues:

  * CVE-2017-7547: Further restrict visibility of
  pg_user_mappings.umoptions, to protect passwords stored as user mapping
  options. (bsc#1051685)

  * CVE-2017-7546: Disallow empty passwords in all password-based
  authentication methods. (bsc#1051684)

  * CVE-2017-7548: lo_put() function ignores ACLs. (bsc#1053259)

  This update was imported from the SUSE:SLE-12:Update update project.");

  script_tag(name:"affected", value:"postgresql94 on openSUSE Leap 42.3, openSUSE Leap 42.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2017:2392-1");
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
  if(!isnull(res = isrpmvuln(pkg:"postgresql94", rpm:"postgresql94~9.4.13~9.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-contrib", rpm:"postgresql94-contrib~9.4.13~9.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-contrib-debuginfo", rpm:"postgresql94-contrib-debuginfo~9.4.13~9.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-debuginfo", rpm:"postgresql94-debuginfo~9.4.13~9.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-debugsource", rpm:"postgresql94-debugsource~9.4.13~9.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-devel", rpm:"postgresql94-devel~9.4.13~9.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-devel-debuginfo", rpm:"postgresql94-devel-debuginfo~9.4.13~9.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-libs-debugsource", rpm:"postgresql94-libs-debugsource~9.4.13~9.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-plperl", rpm:"postgresql94-plperl~9.4.13~9.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-plperl-debuginfo", rpm:"postgresql94-plperl-debuginfo~9.4.13~9.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-plpython", rpm:"postgresql94-plpython~9.4.13~9.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-plpython-debuginfo", rpm:"postgresql94-plpython-debuginfo~9.4.13~9.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-pltcl", rpm:"postgresql94-pltcl~9.4.13~9.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-pltcl-debuginfo", rpm:"postgresql94-pltcl-debuginfo~9.4.13~9.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-server", rpm:"postgresql94-server~9.4.13~9.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-server-debuginfo", rpm:"postgresql94-server-debuginfo~9.4.13~9.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-test", rpm:"postgresql94-test~9.4.13~9.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-docs", rpm:"postgresql94-docs~9.4.13~9.9.1", rls:"openSUSELeap42.2"))) {
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
  if(!isnull(res = isrpmvuln(pkg:"postgresql94", rpm:"postgresql94~9.4.13~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-contrib", rpm:"postgresql94-contrib~9.4.13~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-contrib-debuginfo", rpm:"postgresql94-contrib-debuginfo~9.4.13~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-debuginfo", rpm:"postgresql94-debuginfo~9.4.13~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-debugsource", rpm:"postgresql94-debugsource~9.4.13~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-devel", rpm:"postgresql94-devel~9.4.13~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-devel-debuginfo", rpm:"postgresql94-devel-debuginfo~9.4.13~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-libs-debugsource", rpm:"postgresql94-libs-debugsource~9.4.13~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-plperl", rpm:"postgresql94-plperl~9.4.13~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-plperl-debuginfo", rpm:"postgresql94-plperl-debuginfo~9.4.13~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-plpython", rpm:"postgresql94-plpython~9.4.13~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-plpython-debuginfo", rpm:"postgresql94-plpython-debuginfo~9.4.13~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-pltcl", rpm:"postgresql94-pltcl~9.4.13~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-pltcl-debuginfo", rpm:"postgresql94-pltcl-debuginfo~9.4.13~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-server", rpm:"postgresql94-server~9.4.13~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-server-debuginfo", rpm:"postgresql94-server-debuginfo~9.4.13~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-test", rpm:"postgresql94-test~9.4.13~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-docs", rpm:"postgresql94-docs~9.4.13~12.1", rls:"openSUSELeap42.3"))) {
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
