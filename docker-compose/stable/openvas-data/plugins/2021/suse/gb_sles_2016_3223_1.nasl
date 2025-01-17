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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.3223.1");
  script_cve_id("CVE-2016-9893", "CVE-2016-9895", "CVE-2016-9897", "CVE-2016-9898", "CVE-2016-9899", "CVE-2016-9900", "CVE-2016-9901", "CVE-2016-9902", "CVE-2016-9904", "CVE-2016-9905");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:02 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-03 17:19:00 +0000 (Fri, 03 Aug 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:3223-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:3223-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20163223-1/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-95/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2016:3223-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MozillaFirefox 45 ESR was updated to 45.6 to fix the following issues:
* MFSA 2016-95/CVE-2016-9897: Memory corruption in libGLES
* MFSA 2016-95/CVE-2016-9901: Data from Pocket server improperly sanitized
 before execution
* MFSA 2016-95/CVE-2016-9898: Use-after-free in Editor while manipulating
 DOM subtrees
* MFSA 2016-95/CVE-2016-9899: Use-after-free while manipulating DOM events
 and audio elements
* MFSA 2016-95/CVE-2016-9904: Cross-origin information leak in shared atoms
* MFSA 2016-95/CVE-2016-9905: Crash in EnumerateSubDocuments
* MFSA 2016-95/CVE-2016-9895: CSP bypass using marquee tag
* MFSA 2016-95/CVE-2016-9900: Restricted external resources can be loaded
 by SVG images through data URLs
* MFSA 2016-95/CVE-2016-9893: Memory safety bugs fixed in Firefox 50.1 and
 Firefox ESR 45.6
* MFSA 2016-95/CVE-2016-9902: Pocket extension does not validate the
 origin of events Please see [link moved to references]
for more information.
- Fix fontconfig issue (bsc#1000751) on 32bit systems as well.");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Debuginfo 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~45.6.0esr~66.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~45.6.0esr~66.1", rls:"SLES11.0SP2"))) {
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
