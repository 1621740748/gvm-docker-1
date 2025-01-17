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
  script_oid("1.3.6.1.4.1.25623.1.0.850691");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2015-10-06 12:40:11 +0200 (Tue, 06 Oct 2015)");
  script_cve_id("CVE-2015-4500", "CVE-2015-4501", "CVE-2015-4502", "CVE-2015-4503", "CVE-2015-4504", "CVE-2015-4505", "CVE-2015-4506", "CVE-2015-4507", "CVE-2015-4509", "CVE-2015-4510", "CVE-2015-4511", "CVE-2015-4512", "CVE-2015-4516", "CVE-2015-4517", "CVE-2015-4519", "CVE-2015-4520", "CVE-2015-4521", "CVE-2015-4522", "CVE-2015-7174", "CVE-2015-7175", "CVE-2015-7176", "CVE-2015-7177", "CVE-2015-7178", "CVE-2015-7179", "CVE-2015-7180");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for seamonkey (openSUSE-SU-2015:1681-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'seamonkey'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"seamonkey was updated to fix 25 security issues.

  These security issues were fixed:

  - CVE-2015-4520: Mozilla Firefox before 41.0 and Firefox ESR 38.x before
  38.3 allowed remote attackers to bypass CORS preflight protection
  mechanisms by leveraging (1) duplicate cache-key generation or (2)
  retrieval of a value from an incorrect HTTP Access-Control-* response
  header (bsc#947003).

  - CVE-2015-4521: The ConvertDialogOptions function in Mozilla Firefox
  before 41.0 and Firefox ESR 38.x before 38.3 might allowed remote
  attackers to cause a denial of service (memory corruption and
  application crash) or possibly have unspecified other impact via unknown
  vectors (bsc#947003).

  - CVE-2015-4522: The nsUnicodeToUTF8::GetMaxLength function in Mozilla
  Firefox before 41.0 and Firefox ESR 38.x before 38.3 might allowed
  remote attackers to cause a denial of service (memory corruption and
  application crash) or possibly have unspecified other impact via unknown
  vectors, related to an 'overflow (bsc#947003).

  - CVE-2015-4502: js/src/proxy/Proxy.cpp in Mozilla Firefox before 41.0
  mishandled certain receiver arguments, which allowed remote attackers to
  bypass intended window access restrictions via a crafted web site
  (bsc#947003).

  - CVE-2015-4503: The TCP Socket API implementation in Mozilla Firefox
  before 41.0 mishandled array boundaries that were established with a
  navigator.mozTCPSocket.open method call and send method calls, which
  allowed remote TCP servers to obtain sensitive information from process
  memory by reading packet data, as demonstrated by availability of this
  API in a Firefox OS application (bsc#947003).

  - CVE-2015-4500: Multiple unspecified vulnerabilities in the browser
  engine in Mozilla Firefox before 41.0 and Firefox ESR 38.x before 38.3
  allowed remote attackers to cause a denial of service (memory corruption
  and application crash) or possibly execute arbitrary code via unknown
  vectors (bsc#947003).

  - CVE-2015-4501: Multiple unspecified vulnerabilities in the browser
  engine in Mozilla Firefox before 41.0 allowed remote attackers to cause
  a denial of service (memory corruption and application crash) or
  possibly execute arbitrary code via unknown vectors (bsc#947003).

  - CVE-2015-4506: Buffer overflow in the vp9_init_context_buffers function
  in libvpx, as used in Mozilla Firefox before 41.0 and Firefox ESR 38.x
  before 38.3, allowed remote attackers to execute arbitrary code via a
  crafted VP9 file (bsc#947003).

  - CVE-2015-4507: The SavedStacks class in the JavaScript implementation in
  Mozilla Firefox  ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"seamonkey on openSUSE 13.2, openSUSE 13.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"openSUSE-SU", value:"2015:1681-1");
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
  if(!isnull(res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~2.38~20.2", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-debuginfo", rpm:"seamonkey-debuginfo~2.38~20.2", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-debugsource", rpm:"seamonkey-debugsource~2.38~20.2", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~2.38~20.2", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~2.38~20.2", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-translations-common", rpm:"seamonkey-translations-common~2.38~20.2", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-translations-other", rpm:"seamonkey-translations-other~2.38~20.2", rls:"openSUSE13.2"))) {
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
  if(!isnull(res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~2.38~56.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-debuginfo", rpm:"seamonkey-debuginfo~2.38~56.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-debugsource", rpm:"seamonkey-debugsource~2.38~56.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~2.38~56.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~2.38~56.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-translations-common", rpm:"seamonkey-translations-common~2.38~56.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-translations-other", rpm:"seamonkey-translations-other~2.38~56.1", rls:"openSUSE13.1"))) {
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
