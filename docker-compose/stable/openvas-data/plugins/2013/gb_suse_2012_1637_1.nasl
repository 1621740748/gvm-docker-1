# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2012-12/msg00011.html");
  script_oid("1.3.6.1.4.1.25623.1.0.850385");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2013-03-11 18:29:42 +0530 (Mon, 11 Mar 2013)");
  script_cve_id("CVE-2012-5130", "CVE-2012-5131", "CVE-2012-5132", "CVE-2012-5133",
                "CVE-2012-5134", "CVE-2012-5135", "CVE-2012-5136", "CVE-2012-5137",
                "CVE-2012-5138");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"openSUSE-SU", value:"2012:1637-1");
  script_name("openSUSE: Security Advisory for Chromium (openSUSE-SU-2012:1637-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Chromium'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE12\.1");

  script_tag(name:"affected", value:"Chromium on openSUSE 12.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"insight", value:"Chromium was updated to 25.0.1343

  * Security Fixes (bnc#791234 and bnc#792154):

  - CVE-2012-5131: Corrupt rendering in the Apple OSX
  driver for Intel GPUs

  - CVE-2012-5133: Use-after-free in SVG filters.

  - CVE-2012-5130: Out-of-bounds read in Skia

  - CVE-2012-5132: Browser crash with chunked encoding

  - CVE-2012-5134: Buffer underflow in libxml.

  - CVE-2012-5135: Use-after-free with printing.

  - CVE-2012-5136: Bad cast in input element handling.

  - CVE-2012-5138: Incorrect file path handling

  - CVE-2012-5137: Use-after-free in media source handling

  - Correct build so that proprietary codecs can be used when
  the chromium-ffmpeg package is installed

  - Update to 25.0.1335

  * {gtk} Fixed <input&> selection renders white text on
  white background in apps. (Issue: 158422)

  * Fixed translate infobar button to show selected
  language. (Issue: 155350)

  * Fixed broken Arabic language. (Issue: 158978)

  * Fixed pre-rendering if the preference is disabled at
  start up. (Issue: 159393)

  * Fixed JavaScript rendering issue. (Issue: 159655)

  * No further indications in the ChangeLog

  * Updated V8 - 3.14.5.0

  * Bookmarks are now searched by their title while typing
  into the omnibox with matching bookmarks being shown in
  the autocomplete suggestions pop-down list. Matching is
  done by prefix.

  * Fixed chromium issues 155871, 154173, 155133.

  - Removed patch chomium-ffmpeg-no-pkgconfig.patch

  - Building now internal libffmpegsumo.so based on the
  standard chromium ffmpeg codecs

  - Add a configuration file (/etc/default/chromium) where we
  can indicate flags for the chromium-browser.

  - add explicit buildrequire on libbz2-devel");

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

if(release == "openSUSE12.1") {
  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~25.0.1343.0~1.43.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~25.0.1343.0~1.43.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~25.0.1343.0~1.43.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~25.0.1343.0~1.43.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~25.0.1343.0~1.43.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-desktop-gnome", rpm:"chromium-desktop-gnome~25.0.1343.0~1.43.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-desktop-kde", rpm:"chromium-desktop-kde~25.0.1343.0~1.43.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-ffmpegsumo", rpm:"chromium-ffmpegsumo~25.0.1343.0~1.43.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-ffmpegsumo-debuginfo", rpm:"chromium-ffmpegsumo-debuginfo~25.0.1343.0~1.43.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-suid-helper", rpm:"chromium-suid-helper~25.0.1343.0~1.43.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-suid-helper-debuginfo", rpm:"chromium-suid-helper-debuginfo~25.0.1343.0~1.43.1", rls:"openSUSE12.1"))) {
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
