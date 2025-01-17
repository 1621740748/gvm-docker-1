# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850744");
  script_version("2020-01-31T07:58:03+0000");
  script_tag(name:"last_modification", value:"2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2015-10-13 14:06:52 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2015-0822", "CVE-2015-0827", "CVE-2015-0831", "CVE-2015-0836",
                "CVE-2015-0835");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for Mozilla (SUSE-SU-2015:0446-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MozillaFirefox has been updated to version 31.5.0 ESR to fix five security
  issues.

  These security issues have been fixed:

  * CVE-2015-0836: Multiple unspecified vulnerabilities in the browser
  engine in Mozilla Firefox before 31.5 allowed remote attackers to
  cause a denial of service (memory corruption and application crash)
  or possibly execute arbitrary code via unknown vectors (bnc#917597).

  * CVE-2015-0827: Heap-based buffer overflow in the
  mozilla::gfx::CopyRect function in Mozilla Firefox before 31.5
  allowed remote attackers to obtain sensitive information from
  uninitialized process memory via a malformed SVG graphic
  (bnc#917597).

  * CVE-2015-0835: Multiple unspecified vulnerabilities in the browser
  engine in Mozilla Firefox before 36.0 allowed remote attackers to
  cause a denial of service (memory corruption and application crash)
  or possibly execute arbitrary code via unknown vectors (bnc#917597).

  * CVE-2015-0831: Use-after-free vulnerability in the
  mozilla::dom::IndexedDB::IDBObjectStore::CreateIndex function in
  Mozilla Firefox before 31.5 allowed remote attackers to execute
  arbitrary code or cause a denial of service (heap memory corruption)
  via crafted content that is improperly handled during IndexedDB
  index creation (bnc#917597).

  * CVE-2015-0822: The Form Autocompletion feature in Mozilla Firefox
  before 31.5 allowed remote attackers to read arbitrary files via
  crafted JavaScript code (bnc#917597).

  These non-security issues have been fixed:

  * Reverted desktop file name back to MozillaFirefox.desktop
  (bnc#916196, bnc#917100)

  * Obsolete subpackages of firefox-gcc47 from SLE11-SP1/2, that caused
  problems when upgrading to SLE11-SP3 (bnc#917300)");

  script_tag(name:"affected", value:"Mozilla on SUSE Linux Enterprise Server 11 SP3");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"SUSE-SU", value:"2015:0446-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP3") {
  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~31.5.0esr~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~31.5.0esr~0.7.1", rls:"SLES11.0SP3"))) {
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
