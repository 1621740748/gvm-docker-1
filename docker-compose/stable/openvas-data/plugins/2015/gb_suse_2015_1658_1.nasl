# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850690");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2015-10-02 07:07:08 +0200 (Fri, 02 Oct 2015)");
  script_cve_id("CVE-2015-4476", "CVE-2015-4500", "CVE-2015-4501", "CVE-2015-4502", "CVE-2015-4503", "CVE-2015-4504", "CVE-2015-4505", "CVE-2015-4506", "CVE-2015-4507", "CVE-2015-4508", "CVE-2015-4509", "CVE-2015-4510", "CVE-2015-4511", "CVE-2015-4512", "CVE-2015-4516", "CVE-2015-4517", "CVE-2015-4519", "CVE-2015-4520", "CVE-2015-4521", "CVE-2015-4522", "CVE-2015-7174", "CVE-2015-7175", "CVE-2015-7176", "CVE-2015-7177", "CVE-2015-7178", "CVE-2015-7179", "CVE-2015-7180");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for MozillaFirefox (openSUSE-SU-2015:1658-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MozillaFirefox was updated to Firefox 41.0 (bnc#947003)

  Security issues fixed:

  * MFSA 2015-96/CVE-2015-4500/CVE-2015-4501 Miscellaneous memory safety
  hazards

  * MFSA 2015-97/CVE-2015-4503 (bmo#994337) Memory leak in mozTCPSocket to
  servers

  * MFSA 2015-98/CVE-2015-4504 (bmo#1132467) Out of bounds read in QCMS
  library with ICC V4 profile attributes

  * MFSA 2015-99/CVE-2015-4476 (bmo#1162372) (Android only) Site attribute
  spoofing on Android by pasting URL with unknown scheme

  * MFSA 2015-100/CVE-2015-4505 (bmo#1177861) (Windows only) Arbitrary file
  manipulation by local user through Mozilla updater

  * MFSA 2015-101/CVE-2015-4506 (bmo#1192226) Buffer overflow in libvpx
  while parsing vp9 format video

  * MFSA 2015-102/CVE-2015-4507 (bmo#1192401) Crash when using debugger with
  SavedStacks in JavaScript

  * MFSA 2015-103/CVE-2015-4508 (bmo#1195976) URL spoofing in reader mode

  * MFSA 2015-104/CVE-2015-4510 (bmo#1200004) Use-after-free with shared
  workers and IndexedDB

  * MFSA 2015-105/CVE-2015-4511 (bmo#1200148) Buffer overflow while decoding
  WebM video

  * MFSA 2015-106/CVE-2015-4509 (bmo#1198435) Use-after-free while
  manipulating HTML media content

  * MFSA 2015-107/CVE-2015-4512 (bmo#1170390) Out-of-bounds read during 2D
  canvas display on Linux 16-bit color depth systems

  * MFSA 2015-108/CVE-2015-4502 (bmo#1105045) Scripted proxies can access
  inner window

  * MFSA 2015-109/CVE-2015-4516 (bmo#904886) JavaScript immutable property
  enforcement can be bypassed

  * MFSA 2015-110/CVE-2015-4519 (bmo#1189814) Dragging and dropping images
  exposes final URL after redirects

  * MFSA 2015-111/CVE-2015-4520 (bmo#1200856, bmo#1200869) Errors in the
  handling of CORS preflight request headers

  * MFSA 2015-112/CVE-2015-4517/CVE-2015-4521/CVE-2015-4522/
  CVE-2015-7174/CVE-2015-7175/CVE-2015-7176/CVE-2015-7177/ CVE-2015-7180
  Vulnerabilities found through code inspection

  * MFSA 2015-113/CVE-2015-7178/CVE-2015-7179 (bmo#1189860, bmo#1190526)
  (Windows only) Memory safety errors in libGLES in the ANGLE graphics
  library

  * MFSA 2015-114 (bmo#1167498, bmo#1153672) (Windows only) Information
  disclosure via the High Resolution Time API");

  script_tag(name:"affected", value:"MozillaFirefox on openSUSE 13.2, openSUSE 13.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"openSUSE-SU", value:"2015:1658-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE13\.2|openSUSE13\.1)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE13.2") {
  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~41.0~44.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~41.0~44.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~41.0~44.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~41.0~44.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~41.0~44.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~41.0~44.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~41.0~44.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~41.0~44.1", rls:"openSUSE13.2"))) {
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
  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~41.0~88.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~41.0~88.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~41.0~88.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~41.0~88.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~41.0~88.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~41.0~88.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~41.0~88.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~41.0~88.1", rls:"openSUSE13.1"))) {
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
