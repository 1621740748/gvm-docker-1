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
  script_oid("1.3.6.1.4.1.25623.1.0.851574");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2017-06-27 06:59:45 +0200 (Tue, 27 Jun 2017)");
  script_cve_id("CVE-2017-1000368", "CVE-2017-1000367");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for sudo (openSUSE-SU-2017:1697-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sudo fixes the following security issue:

  - CVE-2017-1000368: A follow-up fix to CVE-2017-1000367, the Linux process
  name could also contain a newline, which could be used to trick sudo to
  read/write to an arbitrary open terminal. (bsc#1042146)

  Also the following non security bug was fixed:

  - Link the 'system_group' plugin with sudo_util library to resolve the
  missing sudo_dso_findsym symbol (bsc#1034560)


  This update was imported from the SUSE:SLE-12-SP2:Update update project.");

  script_tag(name:"affected", value:"sudo on openSUSE Leap 42.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2017:1697-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.2");
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
  if(!isnull(res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.8.10p3~9.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-debuginfo", rpm:"sudo-debuginfo~1.8.10p3~9.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-debugsource", rpm:"sudo-debugsource~1.8.10p3~9.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-devel", rpm:"sudo-devel~1.8.10p3~9.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-test", rpm:"sudo-test~1.8.10p3~9.6.1", rls:"openSUSELeap42.2"))) {
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
