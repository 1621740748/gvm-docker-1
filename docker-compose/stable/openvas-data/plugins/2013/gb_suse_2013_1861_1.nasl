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
  script_oid("1.3.6.1.4.1.25623.1.0.850558");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2013-12-17 12:01:59 +0530 (Tue, 17 Dec 2013)");
  script_cve_id("CVE-2013-2906", "CVE-2013-2907", "CVE-2013-2908", "CVE-2013-2909",
                "CVE-2013-2910", "CVE-2013-2911", "CVE-2013-2912", "CVE-2013-2913",
                "CVE-2013-2914", "CVE-2013-2915", "CVE-2013-2916", "CVE-2013-2917",
                "CVE-2013-2918", "CVE-2013-2919", "CVE-2013-2920", "CVE-2013-2921",
                "CVE-2013-2922", "CVE-2013-2923", "CVE-2013-2924", "CVE-2013-2925",
                "CVE-2013-2926", "CVE-2013-2927", "CVE-2013-2928", "CVE-2013-2931",
                "CVE-2013-6621", "CVE-2013-6622", "CVE-2013-6623", "CVE-2013-6624",
                "CVE-2013-6625", "CVE-2013-6626", "CVE-2013-6627", "CVE-2013-6628",
                "CVE-2013-6629", "CVE-2013-6630", "CVE-2013-6631", "CVE-2013-6632");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2013:1861-1)");

  script_tag(name:"affected", value:"chromium on openSUSE 13.1");

  script_tag(name:"insight", value:"Chromium was updated to 31.0.1650.57: Stable channel update:

  - Security Fixes:

  * CVE-2013-6632: Multiple memory corruption issues.

  - Update to Chromium 31.0.1650.48 Stable Channel update:

  - Security fixes:

  * CVE-2013-6621: Use after free related to speech input
  elements..

  * CVE-2013-6622: Use after free related to media
  elements.

  * CVE-2013-6623: Out of bounds read in SVG.

  * CVE-2013-6624: Use after free related to id
  attribute strings.

  * CVE-2013-6625: Use after free in DOM ranges.

  * CVE-2013-6626: Address bar spoofing related to
  interstitial warnings.

  * CVE-2013-6627: Out of bounds read in HTTP parsing.

  * CVE-2013-6628: Issue with certificates not being
  checked during TLS renegotiation.

  * CVE-2013-2931: Various fixes from internal audits,
  fuzzing and other initiatives.

  * CVE-2013-6629: Read of uninitialized memory in
  libjpeg and libjpeg-turbo.

  * CVE-2013-6630: Read of uninitialized memory in
  libjpeg-turbo.

  * CVE-2013-6631: Use after free in libjingle.

  - Added patch chromium-fix-chromedriver-build.diff to fix
  the  chromedriver build

  - Enable ARM build for Chromium.

  * Added patches chromium-arm-webrtc-fix.patch,
  chromium-fix-arm-icu.patch and
  chromium-fix-arm-sysroot.patch to resolve ARM specific
  build issues

  - Update to Chromium 30.0.1599.114 Stable Channel update:
  fix build for 32bit systems

  - Drop patch chromium-fix-chromedriver-build.diff. This is
  now  fixed upstream

  - For openSUSE versions lower than 13.1, build against the
  in-tree libicu

  - Update to Chromium 30.0.1599.101

  - Security Fixes:
  + CVE-2013-2925: Use after free in XHR
  + CVE-2013-2926: Use after free in editing
  + CVE-2013-2927: Use after free in forms.
  + CVE-2013-2928: Various fixes from internal audits,
  fuzzing and other initiatives.

  - Update to Chromium 30.0.1599.66

  - Easier searching by image

  - A number of new apps/extension APIs

  - Lots of under the hood changes for stability and
  performance

  - Security fixes:
  + CVE-2013-2906: Races in Web Audio
  + CVE-2013-2907: Out of bounds read in Window.prototype
  object
  + CVE-2013-2908: Address bar spoofing related to the
  204 No Content status code
  + CVE-2013-2909: Use after free in inline-block rendering
  + CVE-2013-2910: Use-after-free in Web Audio
  + CVE-2013-2911: Use-after-free in XSLT
  + CVE-2013-2912: Use-after-free in PPAPI
  + CVE-2013-2913: Use-after-free in XML document parsing
  + CVE-2013-2914: Use after free in the Windows color
  chooser   dialog
  + CVE-2013-2915: Address bar spoofing via a malformed
  scheme
  + CVE-2013-2916: ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"openSUSE-SU", value:"2013:1861-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.1");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE13.1") {
  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~31.0.1650.57~8.2", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~31.0.1650.57~8.2", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~31.0.1650.57~8.2", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~31.0.1650.57~8.2", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~31.0.1650.57~8.2", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-desktop-gnome", rpm:"chromium-desktop-gnome~31.0.1650.57~8.2", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-desktop-kde", rpm:"chromium-desktop-kde~31.0.1650.57~8.2", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-ffmpegsumo", rpm:"chromium-ffmpegsumo~31.0.1650.57~8.2", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-ffmpegsumo-debuginfo", rpm:"chromium-ffmpegsumo-debuginfo~31.0.1650.57~8.2", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-suid-helper", rpm:"chromium-suid-helper~31.0.1650.57~8.2", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-suid-helper-debuginfo", rpm:"chromium-suid-helper-debuginfo~31.0.1650.57~8.2", rls:"openSUSE13.1"))) {
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
