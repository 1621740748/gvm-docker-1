# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853902");
  script_version("2021-07-06T12:11:22+0000");
  script_cve_id("CVE-2021-33195", "CVE-2021-33196", "CVE-2021-33197", "CVE-2021-33198");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-07-06 12:11:22 +0000 (Tue, 06 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-02 03:01:18 +0000 (Fri, 02 Jul 2021)");
  script_name("openSUSE: Security Advisory for go1.15 (openSUSE-SU-2021:0950-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0950-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/SGO7YQOALHD4E75OV7S4WAPP2UR3AXKT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.15'
  package(s) announced via the openSUSE-SU-2021:0950-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.15 fixes the following issues:

     Update to 1.15.13.

     Includes these security fixes

  - CVE-2021-33195: net: Lookup functions may return invalid host names
       (bsc#1187443).

  - CVE-2021-33196: archive/zip: malformed archive may cause panic or memory
       exhaustion (bsc#1186622).

  - CVE-2021-33197: net/http/httputil: ReverseProxy forwards Connection
       headers if first one is empty (bsc#1187444)

  - CVE-2021-33198: math/big: (*Rat).SetString with
       '1.770p02041010010011001001' crashes with 'makeslice: len out of
  range'
       (bsc#1187445).

     This update was imported from the SUSE:SLE-15:Update update project.");

  script_tag(name:"affected", value:"'go1.15' package(s) on openSUSE Leap 15.2.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"go1.15", rpm:"go1.15~1.15.13~lp152.20.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.15-doc", rpm:"go1.15-doc~1.15.13~lp152.20.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.15-race", rpm:"go1.15-race~1.15.13~lp152.20.1", rls:"openSUSELeap15.2"))) {
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