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
  script_oid("1.3.6.1.4.1.25623.1.0.851543");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2017-04-29 07:16:59 +0200 (Sat, 29 Apr 2017)");
  script_cve_id("CVE-2014-4975", "CVE-2015-1855", "CVE-2015-3900", "CVE-2015-7551", "CVE-2016-2339");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for ruby2.1 (openSUSE-SU-2017:1128-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby2.1'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This ruby2.1 update to version 2.1.9 fixes the following issues:

  Security issues fixed:

  - CVE-2016-2339: heap overflow vulnerability in the
  Fiddle::Function.new'initialize' (bsc#1018808)

  - CVE-2015-7551: Unsafe tainted string usage in Fiddle and DL (bsc#959495)

  - CVE-2015-3900: hostname validation does not work when fetching gems or
  making API requests (bsc#936032)

  - CVE-2015-1855: Ruby'a OpenSSL extension suffers a vulnerability through
  overly permissive matching of hostnames (bsc#926974)

  - CVE-2014-4975: off-by-one stack-based buffer overflow in the encodes()
  function (bsc#887877)

  Bugfixes:

  - SUSEconnect doesn't handle domain wildcards in no_proxy environment
  variable properly (bsc#1014863)

  - Segmentation fault after pack &amp  ioctl &amp  unpack (bsc#909695)

  - Ruby:HTTP Header injection in 'net/http' (bsc#986630)

  This update was imported from the SUSE:SLE-12:Update update project.");

  script_tag(name:"affected", value:"ruby2.1 on openSUSE Leap 42.2, openSUSE Leap 42.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2017:1128-1");
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
  if(!isnull(res = isrpmvuln(pkg:"libruby2_1-2_1", rpm:"libruby2_1-2_1~2.1.9~8.3.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libruby2_1-2_1-debuginfo", rpm:"libruby2_1-2_1-debuginfo~2.1.9~8.3.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1", rpm:"ruby2.1~2.1.9~8.3.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-debuginfo", rpm:"ruby2.1-debuginfo~2.1.9~8.3.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-debugsource", rpm:"ruby2.1-debugsource~2.1.9~8.3.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-devel", rpm:"ruby2.1-devel~2.1.9~8.3.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-devel-extra", rpm:"ruby2.1-devel-extra~2.1.9~8.3.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-doc", rpm:"ruby2.1-doc~2.1.9~8.3.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-stdlib", rpm:"ruby2.1-stdlib~2.1.9~8.3.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-stdlib-debuginfo", rpm:"ruby2.1-stdlib-debuginfo~2.1.9~8.3.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-doc-ri", rpm:"ruby2.1-doc-ri~2.1.9~8.3.2", rls:"openSUSELeap42.2"))) {
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
  if(!isnull(res = isrpmvuln(pkg:"libruby2_1-2_1", rpm:"libruby2_1-2_1~2.1.9~10.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libruby2_1-2_1-debuginfo", rpm:"libruby2_1-2_1-debuginfo~2.1.9~10.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1", rpm:"ruby2.1~2.1.9~10.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-debuginfo", rpm:"ruby2.1-debuginfo~2.1.9~10.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-debugsource", rpm:"ruby2.1-debugsource~2.1.9~10.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-devel", rpm:"ruby2.1-devel~2.1.9~10.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-devel-extra", rpm:"ruby2.1-devel-extra~2.1.9~10.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-doc", rpm:"ruby2.1-doc~2.1.9~10.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-stdlib", rpm:"ruby2.1-stdlib~2.1.9~10.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-stdlib-debuginfo", rpm:"ruby2.1-stdlib-debuginfo~2.1.9~10.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uby2.1-doc-ri", rpm:"uby2.1-doc-ri~2.1.9~10.2", rls:"openSUSELeap42.1"))) {
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
