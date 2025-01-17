# Copyright (C) 2017 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.851652");
  script_version("2020-11-12T09:56:04+0000");
  script_tag(name:"last_modification", value:"2020-11-12 09:56:04 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"creation_date", value:"2017-11-26 07:32:39 +0100 (Sun, 26 Nov 2017)");
  script_cve_id("CVE-2017-16837");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for tboot (openSUSE-SU-2017:3100-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tboot'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tboot fixes the following issues:

  Security issues fixed:

  - CVE-2017-16837: Fix tbootfailed to validate a number of immutable
  function pointers, which could allow an attacker to bypass the chain of
  trust and execute arbitrary code (boo#1068390).

  - Make tboot package compatible with OpenSSL 1.1.0 for SLE-15 support
  (boo#1067229).

  Bug fixes:

  - Update to new upstream version. See the referenced release notes for details (1.9.6
  1.9.5, FATE#321510  1.9.4, FATE#320665  1.8.3, FATE#318542).

  - Fix some gcc7 warnings that lead to errors. (boo#1041264)

  - Fix wrong pvops kernel config matching (boo#981948)

  - Fix an excessive stack usage pattern that could lead to resets/crashes
  (boo#967441)

  - fixes a boot issue on Skylake (boo#964408)

  - Trim filler words from description  use modern macros over shell vars.

  - Add reproducible.patch to call gzip -n to make build fully reproducible.");

  script_tag(name:"affected", value:"tboot on openSUSE Leap 42.3, openSUSE Leap 42.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2017:3100-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.2|openSUSELeap42\.3)");

  script_xref(name:"URL", value:"https://sourceforge.net/p/tboot/code/ci/default/tree/CHANGELOG");

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
  if(!isnull(res = isrpmvuln(pkg:"tboot-20170711", rpm:"tboot-20170711~1.9.6~4.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tboot-debuginfo-20170711", rpm:"tboot-debuginfo-20170711~1.9.6~4.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tboot-debugsource-20170711", rpm:"tboot-debugsource-20170711~1.9.6~4.3.1", rls:"openSUSELeap42.2"))) {
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
  if(!isnull(res = isrpmvuln(pkg:"tboot-20170711", rpm:"tboot-20170711~1.9.6~7.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tboot-debuginfo-20170711", rpm:"tboot-debuginfo-20170711~1.9.6~7.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tboot-debugsource-20170711", rpm:"tboot-debugsource-20170711~1.9.6~7.1", rls:"openSUSELeap42.3"))) {
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
