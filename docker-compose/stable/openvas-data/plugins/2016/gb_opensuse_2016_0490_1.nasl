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
  script_oid("1.3.6.1.4.1.25623.1.0.851206");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2016-03-01 11:08:55 +0530 (Tue, 01 Mar 2016)");
  script_cve_id("CVE-2014-9761", "CVE-2015-7547", "CVE-2015-8776", "CVE-2015-8777",
                "CVE-2015-8778", "CVE-2015-8779");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for glibc (openSUSE-SU-2016:0490-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for glibc fixes the following security issues:

  - CVE-2015-7547: A stack-based buffer overflow in getaddrinfo allowed
  remote attackers to cause a crash or execute arbitrary code via crafted
  and timed DNS responses (bsc#961721)

  - CVE-2015-8777: Insufficient checking of LD_POINTER_GUARD environment
  variable allowed local attackers to bypass the pointer guarding
  protection of the dynamic loader on set-user-ID and set-group-ID
  programs (bsc#950944)

  - CVE-2015-8776: Out-of-range time values passed to the strftime function
  may cause it to crash, leading to a denial of service, or potentially
  disclosure information (bsc#962736)

  - CVE-2015-8778: Integer overflow in hcreate and hcreate_r could have
  caused an out-of-bound memory access. leading to application crashes or,
  potentially, arbitrary code execution (bsc#962737)

  - CVE-2014-9761: A stack overflow (unbounded alloca) could have caused
  applications which process long strings with the nan function to crash
  or, potentially, execute arbitrary code. (bsc#962738)

  - CVE-2015-8779: A stack overflow (unbounded alloca) in the catopen
  function could have caused applications which pass long strings to the
  catopen function to crash or, potentially execute arbitrary code.
  (bsc#962739)

  The following non-security bugs were fixed:

  - bsc#955647: Resource leak in resolver

  - bsc#956716: Don't do lock elision on an error checking mutex

  - bsc#958315: Reinitialize dl_load_write_lock on fork

  This update was imported from the SUSE:SLE-12-SP1:Update update project.");

  script_tag(name:"affected", value:"glibc on openSUSE Leap 42.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:0490-1");
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
  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-debuginfo", rpm:"glibc-debuginfo~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-debugsource", rpm:"glibc-debugsource~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-debuginfo", rpm:"glibc-devel-debuginfo~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-static", rpm:"glibc-devel-static~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale", rpm:"glibc-locale~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale-debuginfo", rpm:"glibc-locale-debuginfo~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-extra", rpm:"glibc-extra~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-extra-debuginfo", rpm:"glibc-extra-debuginfo~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils-debuginfo", rpm:"glibc-utils-debuginfo~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils-debugsource", rpm:"glibc-utils-debugsource~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd-debuginfo", rpm:"nscd-debuginfo~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-32bit", rpm:"glibc-32bit~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-debuginfo-32bit", rpm:"glibc-debuginfo-32bit~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-32bit", rpm:"glibc-devel-32bit~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-debuginfo-32bit", rpm:"glibc-devel-debuginfo-32bit~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-static-32bit", rpm:"glibc-devel-static-32bit~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale-32bit", rpm:"glibc-locale-32bit~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale-debuginfo-32bit", rpm:"glibc-locale-debuginfo-32bit~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile-32bit", rpm:"glibc-profile-32bit~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils-32bit", rpm:"glibc-utils-32bit~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils-debuginfo-32bit", rpm:"glibc-utils-debuginfo-32bit~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-html", rpm:"glibc-html~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-info", rpm:"glibc-info~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-obsolete", rpm:"glibc-obsolete~2.19~19.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-obsolete-debuginfo", rpm:"glibc-obsolete-debuginfo~2.19~19.1", rls:"openSUSELeap42.1"))) {
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
