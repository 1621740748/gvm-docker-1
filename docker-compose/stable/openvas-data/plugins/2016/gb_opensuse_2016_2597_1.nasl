# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851416");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2016-10-24 05:53:08 +0200 (Mon, 24 Oct 2016)");
  script_cve_id("CVE-2016-5181", "CVE-2016-5182", "CVE-2016-5183", "CVE-2016-5184",
                "CVE-2016-5185", "CVE-2016-5186", "CVE-2016-5187", "CVE-2016-5188",
                "CVE-2016-5189", "CVE-2016-5190", "CVE-2016-5191", "CVE-2016-5192",
                "CVE-2016-5193");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for Chromium (openSUSE-SU-2016:2597-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Chromium'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium was updated to 54.0.2840.59 to fix security issues and bugs.

  The following security issues are fixed (bnc#1004465):

  - CVE-2016-5181: Universal XSS in Blink

  - CVE-2016-5182: Heap overflow in Blink

  - CVE-2016-5183: Use after free in PDFium

  - CVE-2016-5184: Use after free in PDFium

  - CVE-2016-5185: Use after free in Blink

  - CVE-2016-5187: URL spoofing

  - CVE-2016-5188: UI spoofing

  - CVE-2016-5192: Cross-origin bypass in Blink

  - CVE-2016-5189: URL spoofing

  - CVE-2016-5186: Out of bounds read in DevTools

  - CVE-2016-5191: Universal XSS in Bookmarks

  - CVE-2016-5190: Use after free in Internals

  - CVE-2016-5193: Scheme bypass

  The following bugs were fixed:

  - bnc#1000019: display issues in full screen mode, add

  - -ui-disable-partial-swap to the launcher

  The following packaging changes are included:

  - The desktop sub-packages are no obsolete

  - The package now uses the system variants of some bundled libraries

  - The hangouts extension is now built");

  script_tag(name:"affected", value:"Chromium on openSUSE Leap 42.1, openSUSE 13.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:2597-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE13.2")
{

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~54.0.2840.59~131.2", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~54.0.2840.59~131.2", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~54.0.2840.59~131.2", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~54.0.2840.59~131.2", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~54.0.2840.59~131.2", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-ffmpegsumo", rpm:"chromium-ffmpegsumo~54.0.2840.59~131.2", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-ffmpegsumo-debuginfo", rpm:"chromium-ffmpegsumo-debuginfo~54.0.2840.59~131.2", rls:"openSUSE13.2"))) {
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
