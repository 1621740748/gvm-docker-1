# Copyright (C) 2012 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850244");
  script_version("2020-04-21T06:28:23+0000");
  script_tag(name:"last_modification", value:"2020-04-21 06:28:23 +0000 (Tue, 21 Apr 2020)");
  script_tag(name:"creation_date", value:"2012-08-02 22:38:33 +0530 (Thu, 02 Aug 2012)");
  script_cve_id("CVE-2011-3026");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"openSUSE-SU", value:"2012:0316-1");
  script_name("openSUSE: Security Advisory for libpng12 (openSUSE-SU-2012:0316-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpng12'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE11\.4");

  script_tag(name:"affected", value:"libpng12 on openSUSE 11.4");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"insight", value:"A heap-based buffer overflow in libpng was fixed that could
  potentially be exploited by attackers to execute arbitrary
  code or cause an application to crash (CVE-2011-3026).

  libpng 1.2 was updated to 1.2.47 to fix this issue.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE11.4") {
  if(!isnull(res = isrpmvuln(pkg:"libpng12-0", rpm:"libpng12-0~1.2.47~0.8.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng12-compat-devel", rpm:"libpng12-compat-devel~1.2.47~0.8.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng12-devel", rpm:"libpng12-devel~1.2.47~0.8.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng14-14", rpm:"libpng14-14~1.4.4~3.6.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng14-compat-devel", rpm:"libpng14-compat-devel~1.4.4~3.6.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng14-devel", rpm:"libpng14-devel~1.4.4~3.6.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng12-0-32bit", rpm:"libpng12-0-32bit~1.2.47~0.8.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng12-compat-devel-32bit", rpm:"libpng12-compat-devel-32bit~1.2.47~0.8.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng12-devel-32bit", rpm:"libpng12-devel-32bit~1.2.47~0.8.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng14-14-32bit", rpm:"libpng14-14-32bit~1.4.4~3.6.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng14-compat-devel-32bit", rpm:"libpng14-compat-devel-32bit~1.4.4~3.6.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng14-devel-32bit", rpm:"libpng14-devel-32bit~1.4.4~3.6.1", rls:"openSUSE11.4"))) {
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
