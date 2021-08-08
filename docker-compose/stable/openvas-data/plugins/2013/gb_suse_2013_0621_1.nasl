# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850457");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2013-11-19 14:05:45 +0530 (Tue, 19 Nov 2013)");
  script_cve_id("CVE-2013-1362");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("openSUSE: Security Advisory for NRPE (openSUSE-SU-2013:0621-1)");

  script_tag(name:"affected", value:"NRPE on openSUSE 12.2, openSUSE 12.1");

  script_tag(name:"insight", value:"NRPE (the Nagios Remote Plug-In Executor) allows the
  passing of $() to plugins/scripts which, if run under bash,
  will execute that shell command under a subprocess and pass
  the output as a parameter to the called script. Using this,
  it is possible to get called scripts, such as check_http,
  to execute arbitrary commands under the uid that
  NRPE/nagios is running as (typically, 'nagios').

  With this update NRPE will deny remote requests containing
  a bash command substitution.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"openSUSE-SU", value:"2013:0621-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'NRPE'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE12\.2|openSUSE12\.1)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE12.2") {
  if(!isnull(res = isrpmvuln(pkg:"nagios-nrpe", rpm:"nagios-nrpe~2.12~30.9.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-nrpe-debuginfo", rpm:"nagios-nrpe-debuginfo~2.12~30.9.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-nrpe-debugsource", rpm:"nagios-nrpe-debugsource~2.12~30.9.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-nrpe-doc", rpm:"nagios-nrpe-doc~2.12~30.9.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-plugins-nrpe", rpm:"nagios-plugins-nrpe~2.12~30.9.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-plugins-nrpe-debuginfo", rpm:"nagios-plugins-nrpe-debuginfo~2.12~30.9.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSE12.1") {
  if(!isnull(res = isrpmvuln(pkg:"nagios-nrpe", rpm:"nagios-nrpe~2.12~27.7.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-nrpe-debuginfo", rpm:"nagios-nrpe-debuginfo~2.12~27.7.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-nrpe-debugsource", rpm:"nagios-nrpe-debugsource~2.12~27.7.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-nrpe-doc", rpm:"nagios-nrpe-doc~2.12~27.7.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-plugins-nrpe", rpm:"nagios-plugins-nrpe~2.12~27.7.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-plugins-nrpe-debuginfo", rpm:"nagios-plugins-nrpe-debuginfo~2.12~27.7.1", rls:"openSUSE12.1"))) {
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
