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
  script_oid("1.3.6.1.4.1.25623.1.0.853654");
  script_version("2021-04-21T07:29:02+0000");
  script_cve_id("CVE-2021-0326");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-04-21 07:29:02 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 04:58:57 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for wpa_supplicant (openSUSE-SU-2021:0284-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0284-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YI2F4UP2SUM3KDNM2O5RK57I3NEYBJ26");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wpa_supplicant'
  package(s) announced via the openSUSE-SU-2021:0284-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for wpa_supplicant fixes the following issues:

  - CVE-2021-0326: P2P group information processing vulnerability
       (bsc#1181777).

     This update was imported from the SUSE:SLE-15:Update update project.");

  script_tag(name:"affected", value:"'wpa_supplicant' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~2.9~lp152.8.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant-debuginfo", rpm:"wpa_supplicant-debuginfo~2.9~lp152.8.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant-debugsource", rpm:"wpa_supplicant-debugsource~2.9~lp152.8.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant-gui", rpm:"wpa_supplicant-gui~2.9~lp152.8.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant-gui-debuginfo", rpm:"wpa_supplicant-gui-debuginfo~2.9~lp152.8.6.1", rls:"openSUSELeap15.2"))) {
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