# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850616");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2014-10-01 16:59:10 +0530 (Wed, 01 Oct 2014)");
  script_cve_id("CVE-2014-7169", "CVE-2014-7186", "CVE-2014-7187", "CVE-2014-6271");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("openSUSE: Security Advisory for bash (openSUSE-SU-2014:1242-1)");

  script_tag(name:"insight", value:"The command-line shell 'bash' evaluates environment variables, which
  allows the injection of characters and might be used to access files on
  the system in some circumstances (CVE-2014-7169).

  Please note that this issue is different from a previously fixed
  vulnerability tracked under CVE-2014-6271 and it is less serious due to
  the special, non-default system configuration that is needed to create an
  exploitable situation.

  To remove further exploitation potential we now limit the
  function-in-environment variable to variables prefixed with BASH_FUNC_ .
  This hardening feature is work in progress and might be improved in later
  updates.

  Additionally two more security issues were fixed in bash: CVE-2014-7186:
  Nested HERE documents could lead to a crash of bash.

  CVE-2014-7187: Nesting of for loops could lead to a crash of bash.");

  script_tag(name:"affected", value:"bash on openSUSE 13.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"openSUSE-SU", value:"2014:1242-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'bash'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE13.1") {
  if(!isnull(res = isrpmvuln(pkg:"bash", rpm:"bash~4.2~68.8.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bash-debuginfo", rpm:"bash-debuginfo~4.2~68.8.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bash-debugsource", rpm:"bash-debugsource~4.2~68.8.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bash-devel", rpm:"bash-devel~4.2~68.8.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bash-loadables", rpm:"bash-loadables~4.2~68.8.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bash-loadables-debuginfo", rpm:"bash-loadables-debuginfo~4.2~68.8.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreadline6", rpm:"libreadline6~6.2~68.8.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreadline6-debuginfo", rpm:"libreadline6-debuginfo~6.2~68.8.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"readline-devel", rpm:"readline-devel~6.2~68.8.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bash-debuginfo-32bit", rpm:"bash-debuginfo-32bit~4.2~68.8.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreadline6-32bit", rpm:"libreadline6-32bit~6.2~68.8.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreadline6-debuginfo-32bit", rpm:"libreadline6-debuginfo-32bit~6.2~68.8.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"readline-devel-32bit", rpm:"readline-devel-32bit~6.2~68.8.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bash-doc", rpm:"bash-doc~4.2~68.8.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bash-lang", rpm:"bash-lang~4.2~68.8.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eadline-doc", rpm:"eadline-doc~6.2~68.8.1", rls:"openSUSE13.1"))) {
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
