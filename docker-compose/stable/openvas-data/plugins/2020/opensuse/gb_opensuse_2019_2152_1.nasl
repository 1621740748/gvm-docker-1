# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852838");
  script_version("2020-01-31T08:04:39+0000");
  script_cve_id("CVE-2019-13659", "CVE-2019-13660", "CVE-2019-13661", "CVE-2019-13662",
                "CVE-2019-13663", "CVE-2019-13664", "CVE-2019-13665", "CVE-2019-13666",
                "CVE-2019-13667", "CVE-2019-13668", "CVE-2019-13669", "CVE-2019-13670",
                "CVE-2019-13671", "CVE-2019-13673", "CVE-2019-13674", "CVE-2019-13675",
                "CVE-2019-13676", "CVE-2019-13677", "CVE-2019-13678", "CVE-2019-13679",
                "CVE-2019-13680", "CVE-2019-13681", "CVE-2019-13682", "CVE-2019-13683",
                "CVE-2019-5870", "CVE-2019-5871", "CVE-2019-5872", "CVE-2019-5874",
                "CVE-2019-5875", "CVE-2019-5876", "CVE-2019-5877", "CVE-2019-5878",
                "CVE-2019-5879", "CVE-2019-5880", "CVE-2019-5881");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-31 08:04:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-09 09:34:52 +0000 (Thu, 09 Jan 2020)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2019:2152-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2019:2152-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-09/msg00050.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2019:2152-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium to 77.0.3865.75 fixes the following issues:

  Security issues fixed:

  - CVE-2019-5870: Fixed a use-after-free in media. (boo#1150425)

  - CVE-2019-5871: Fixed a heap overflow in Skia. (boo#1150425)

  - CVE-2019-5872: Fixed a use-after-free in Mojo (boo#1150425)

  - CVE-2019-5874: Fixed a behavior that made external URIs trigger other
  browsers. (boo#1150425)

  - CVE-2019-5875: Fixed a URL bar spoof via download redirect. (boo#1150425)

  - CVE-2019-5876: Fixed a use-after-free in media (boo#1150425)

  - CVE-2019-5877: Fixed an out-of-bounds access in V8. (boo#1150425)

  - CVE-2019-5878: Fixed a use-after-free in V8. (boo#1150425)

  - CVE-2019-5879: Fixed an extension issue that allowed the bypass of a
  same origin policy. (boo#1150425)

  - CVE-2019-5880: Fixed a SameSite cookie bypass. (boo#1150425)

  - CVE-2019-5881: Fixed an arbitrary read in SwiftShader. (boo#1150425)

  - CVE-2019-13659: Fixed an URL spoof. (boo#1150425)

  - CVE-2019-13660: Fixed a full screen notification overlap. (boo#1150425)

  - CVE-2019-13661: Fixed a full screen notification spoof. (boo#1150425)

  - CVE-2019-13662: Fixed a CSP bypass. (boo#1150425)

  - CVE-2019-13663: Fixed an IDN spoof. (boo#1150425)

  - CVE-2019-13664: Fixed a CSRF bypass. (boo#1150425)

  - CVE-2019-13665: Fixed a multiple file download protection bypass.
  (boo#1150425)

  - CVE-2019-13666: Fixed a side channel weakness using storage size
  estimate. (boo#1150425)

  - CVE-2019-13667: Fixed a URI bar spoof when using external app URIs.
  (boo#1150425)

  - CVE-2019-13668: Fixed a global window leak via console. (boo#1150425)

  - CVE-2019-13669: Fixed an HTTP authentication spoof. (boo#1150425)

  - CVE-2019-13670: Fixed a V8 memory corruption in regex. (boo#1150425)

  - CVE-2019-13671: Fixed a dialog box that failed to show the origin.
  (boo#1150425)

  - CVE-2019-13673: Fixed a cross-origin information leak using devtools.
  (boo#1150425)

  - CVE-2019-13674: Fixed an IDN spoofing opportunity. (boo#1150425)

  - CVE-2019-13675: Fixed an error that allowed extensions to be disabled by
  trailing slash. (boo#1150425)

  - CVE-2019-13676: Fixed a mistakenly shown Google URI in certificate
  warnings. (boo#1150425)

  - CVE-2019-13677: Fixed a lack of isolation in Chrome web store origin.
  (boo#1150425)

  - CVE-2019-13678: Fixed a download dialog spoofing opportunity.
  (boo#1150425)

  - CVE-2019-13679: Fixed a the necessity of a user gesture for printing.
  (boo#1150425)

  - CVE-2019-13680: Fixed an IP address spoofing error. (boo#1150425)

  - CVE-2019-13681: Fixed a bypass on download restrictions. (boo#1150425)

  - CVE ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~77.0.3865.75~lp151.2.30.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~77.0.3865.75~lp151.2.30.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~77.0.3865.75~lp151.2.30.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~77.0.3865.75~lp151.2.30.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~77.0.3865.75~lp151.2.30.1", rls:"openSUSELeap15.1"))) {
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
