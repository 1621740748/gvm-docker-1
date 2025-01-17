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
  script_oid("1.3.6.1.4.1.25623.1.0.853825");
  script_version("2021-07-01T08:10:49+0000");
  script_cve_id("CVE-2021-32490", "CVE-2021-32491", "CVE-2021-32492", "CVE-2021-32493");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-01 08:10:49 +0000 (Thu, 01 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-05-24 03:01:03 +0000 (Mon, 24 May 2021)");
  script_name("openSUSE: Security Advisory for djvulibre (openSUSE-SU-2021:0759-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0759-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VWUVFLJ5WIUYL2E7ZRZKXICPKCTWQHHD");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'djvulibre'
  package(s) announced via the openSUSE-SU-2021:0759-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for djvulibre fixes the following issues:

  - CVE-2021-32490 [bsc#1185895]: Out of bounds write in function
       DJVU:filter_bv() via crafted djvu file

  - CVE-2021-32491 [bsc#1185900]: Integer overflow in function render() in
       tools/ddjvu via crafted djvu file

  - CVE-2021-32492 [bsc#1185904]: Out of bounds read in function
       DJVU:DataPool:has_data() via crafted djvu file

  - CVE-2021-32493 [bsc#1185905]: Heap buffer overflow in function
       DJVU:GBitmap:decode() via crafted djvu file

     This update was imported from the SUSE:SLE-15-SP2:Update update project.");

  script_tag(name:"affected", value:"'djvulibre' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"djvulibre", rpm:"djvulibre~3.5.27~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"djvulibre-debuginfo", rpm:"djvulibre-debuginfo~3.5.27~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"djvulibre-debugsource", rpm:"djvulibre-debugsource~3.5.27~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdjvulibre-devel", rpm:"libdjvulibre-devel~3.5.27~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdjvulibre21", rpm:"libdjvulibre21~3.5.27~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdjvulibre21-debuginfo", rpm:"libdjvulibre21-debuginfo~3.5.27~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"djvulibre-doc", rpm:"djvulibre-doc~3.5.27~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
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