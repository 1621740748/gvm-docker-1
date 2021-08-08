# Copyright (C) 2016 Eero Volotinen
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
  script_oid("1.3.6.1.4.1.25623.1.0.120662");
  script_version("2020-03-13T13:19:50+0000");
  script_tag(name:"creation_date", value:"2016-03-31 08:02:05 +0300 (Thu, 31 Mar 2016)");
  script_tag(name:"last_modification", value:"2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)");
  script_name("Amazon Linux: Security Advisory (ALAS-2016-672)");
  script_tag(name:"insight", value:"An integer truncation flaw (CVE-2016-2315 ) and an integer overflow flaw (CVE-2016-2324 ), both leading to a heap-based buffer overflow, were found in the way Git processed certain path information. A remote attacker could create a specially crafted Git repository that would cause a Git client or server to crash or, possibly, execute arbitrary code.");
  script_tag(name:"solution", value:"Run yum update git to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-672.html");
  script_cve_id("CVE-2016-2315", "CVE-2016-2324");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"The remote host is missing an update announced via the referenced Security Advisory.");
  script_copyright("Copyright (C) 2016 Eero Volotinen");
  script_family("Amazon Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "AMAZON") {
  if(!isnull(res = isrpmvuln(pkg:"git", rpm:"git~2.7.4~1.47.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-svn", rpm:"git-svn~2.7.4~1.47.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-daemon", rpm:"git-daemon~2.7.4~1.47.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-debuginfo", rpm:"git-debuginfo~2.7.4~1.47.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-git-el", rpm:"emacs-git-el~2.7.4~1.47.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-all", rpm:"git-all~2.7.4~1.47.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-git", rpm:"emacs-git~2.7.4~1.47.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gitweb", rpm:"gitweb~2.7.4~1.47.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-bzr", rpm:"git-bzr~2.7.4~1.47.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-p4", rpm:"git-p4~2.7.4~1.47.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Git", rpm:"perl-Git~2.7.4~1.47.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Git-SVN", rpm:"perl-Git-SVN~2.7.4~1.47.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-hg", rpm:"git-hg~2.7.4~1.47.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-email", rpm:"git-email~2.7.4~1.47.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-cvs", rpm:"git-cvs~2.7.4~1.47.amzn1", rls:"AMAZON"))) {
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
