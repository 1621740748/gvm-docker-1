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
  script_oid("1.3.6.1.4.1.25623.1.0.850603");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2014-08-11 12:25:57 +0200 (Mon, 11 Aug 2014)");
  script_cve_id("CVE-2014-1544", "CVE-2014-1547", "CVE-2014-1548", "CVE-2014-1555",
                "CVE-2014-1556", "CVE-2014-1557");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("openSUSE: Security Advisory for MozillaThunderbird (openSUSE-SU-2014:0976-1)");

  script_tag(name:"affected", value:"MozillaThunderbird on openSUSE 13.1, openSUSE 12.3");

  script_tag(name:"insight", value:"MozillaThunderbird was updated to Thunderbird 24.7.0 (bnc#887746)

  * MFSA 2014-56/CVE-2014-1547/CVE-2014-1548 Miscellaneous memory safety
  hazards

  * MFSA 2014-61/CVE-2014-1555 (bmo#1023121) Use-after-free with
  FireOnStateChange event

  * MFSA 2014-62/CVE-2014-1556 (bmo#1028891) Exploitable WebGL crash with
  Cesium JavaScript library

  * MFSA 2014-63/CVE-2014-1544 (bmo#963150) Use-after-free while when
  manipulating certificates in the trusted cache (solved with NSS 3.16.2
  requirement)

  * MFSA 2014-64/CVE-2014-1557 (bmo#913805) Crash in Skia library when
  scaling high quality images

  A standalone enigmail 1.7 package that was previously built as part of
  MozillaThunderbird was added.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"openSUSE-SU", value:"2014:0976-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE12\.3|openSUSE13\.1)");

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
  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~24.7.0~61.55.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~24.7.0~61.55.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~24.7.0~61.55.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~24.7.0~61.55.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~24.7.0~61.55.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~24.7.0~61.55.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~24.7.0~61.55.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"enigmail", rpm:"enigmail~1.7~2.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"enigmail-debuginfo", rpm:"enigmail-debuginfo~1.7~2.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"enigmail-debugsource", rpm:"enigmail-debugsource~1.7~2.1", rls:"openSUSE12.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSE13.1") {
  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~24.7.0~70.27.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~24.7.0~70.27.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~24.7.0~70.27.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~24.7.0~70.27.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~24.7.0~70.27.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~24.7.0~70.27.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~24.7.0~70.27.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"enigmail", rpm:"enigmail~1.7~2.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"enigmail-debuginfo", rpm:"enigmail-debuginfo~1.7~2.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"enigmail-debugsource", rpm:"enigmail-debugsource~1.7~2.1", rls:"openSUSE13.1"))) {
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
