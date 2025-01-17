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
  script_oid("1.3.6.1.4.1.25623.1.0.850599");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2014-08-05 16:50:18 +0530 (Tue, 05 Aug 2014)");
  script_cve_id("CVE-2014-4038", "CVE-2014-4039");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_name("openSUSE: Security Advisory for ppc64-diag (openSUSE-SU-2014:0953-2)");

  script_tag(name:"affected", value:"ppc64-diag on openSUSE 12.3");

  script_tag(name:"insight", value:"ppc64-diag was updated to fix tmp race issues (CVE-2014-4038) and a file
  disclosure problem in snapshot tarball generation (CVE-2014-4039).");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"openSUSE-SU", value:"2014:0953-2");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ppc64-diag'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE12\.3");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE12.3") {
  if(!isnull(res = isrpmvuln(pkg:"ppc64-diag", rpm:"ppc64-diag~2.6.0~2.4.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ppc64-diag-debuginfo", rpm:"ppc64-diag-debuginfo~2.6.0~2.4.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ppc64-diag-debugsource", rpm:"ppc64-diag-debugsource~2.6.0~2.4.1", rls:"openSUSE12.3"))) {
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
