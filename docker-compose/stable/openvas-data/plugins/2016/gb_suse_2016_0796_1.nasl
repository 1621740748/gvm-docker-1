# Copyright (C) 2016 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851241");
  script_version("2020-01-31T07:58:03+0000");
  script_tag(name:"last_modification", value:"2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2016-03-17 05:11:28 +0100 (Thu, 17 Mar 2016)");
  script_cve_id("CVE-2016-2315", "CVE-2016-2324");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for git (SUSE-SU-2016:0796-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for git fixes a buffer overflow issue that had the potential
  to be abused for remote execution of arbitrary code (CVE-2016-2315,
  CVE-2016-2324, bsc#971328).");

  script_tag(name:"affected", value:"git on SUSE Linux Enterprise Server 12");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"SUSE-SU", value:"2016:0796-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES12\.0SP0");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES12.0SP0") {
  if(!isnull(res = isrpmvuln(pkg:"git-core", rpm:"git-core~1.8.5.6~18.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-core-debuginfo", rpm:"git-core-debuginfo~1.8.5.6~18.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-debugsource", rpm:"git-debugsource~1.8.5.6~18.1", rls:"SLES12.0SP0"))) {
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
