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
  script_oid("1.3.6.1.4.1.25623.1.0.853829");
  script_version("2021-06-15T08:02:31+0000");
  script_cve_id("CVE-2021-3520");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-06-15 08:02:31 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-05-24 03:01:36 +0000 (Mon, 24 May 2021)");
  script_name("openSUSE: Security Advisory for lz4 (openSUSE-SU-2021:0760-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0760-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/Y6JSYGHG2J4E7C5MDUDUDEILIMZKTM7H");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lz4'
  package(s) announced via the openSUSE-SU-2021:0760-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for lz4 fixes the following issues:

  - CVE-2021-3520: Fixed memory corruption due to an integer overflow bug
       caused by memmove argument (bsc#1185438).

     This update was imported from the SUSE:SLE-15:Update update project.");

  script_tag(name:"affected", value:"'lz4' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"liblz4-1", rpm:"liblz4-1~1.8.0~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblz4-1-debuginfo", rpm:"liblz4-1-debuginfo~1.8.0~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblz4-devel", rpm:"liblz4-devel~1.8.0~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lz4", rpm:"lz4~1.8.0~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lz4-debuginfo", rpm:"lz4-debuginfo~1.8.0~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lz4-debugsource", rpm:"lz4-debugsource~1.8.0~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblz4-1-32bit", rpm:"liblz4-1-32bit~1.8.0~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblz4-1-32bit-debuginfo", rpm:"liblz4-1-32bit-debuginfo~1.8.0~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
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